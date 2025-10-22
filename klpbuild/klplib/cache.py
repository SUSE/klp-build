from datetime import datetime, timedelta
import logging
import os
import pickle
import zlib
from functools import wraps
from pathlib import Path

CACHE_PATH="/tmp/klp-build/"
__is_cache_enabled = False

# FIXME: I don't like this at all, it's just temporary
# TODO: make it recursive so that it works with list of klp build objs
def __simple_args_hash(*args):
    args_key = []
    for a in args:
        if getattr(a, "__klp_build_obj_hash__", False):
            # This is to have a custom hash on our objects so that the address
            # doesn't corrupt the hash
            args_key.append(repr(a.__klp_build_obj_hash__()))
        else:
            args_key.append(repr(a))

    sep = "|"
    combined = sep.join(args_key).encode("utf-8")
    hash = zlib.crc32(combined) & 0xFFFFFFFF
    return hex(hash)[2:].upper()


def __get_cache_file_name(cache_id):
    cache_dir = Path(CACHE_PATH)
    cache_dir.mkdir(parents=True, exist_ok=True)
    return  cache_dir/cache_id


def __is_cache_valid(cache_id):
    stamp_file_path = __get_cache_file_name(cache_id)
    if not os.path.exists(stamp_file_path):
        return False

    last_run = datetime.fromtimestamp(os.path.getmtime(stamp_file_path))
    valid = datetime.now() - last_run < timedelta(days=1)

    if valid:
        logging.debug(f"[CACHE] {cache_id} still valid" )
    else:
        logging.debug(f"[CACHE] {cache_id} no longer valid" )
    return valid

def __get_cache_content(cache_id):
    logging.debug("[CACHE] Loading %s", cache_id)

    stamp_file_path = __get_cache_file_name(cache_id)
    try:
        with open(stamp_file_path, "rb") as f:
            return pickle.load(f)
    except EOFError:
        # Empty file — silently ignore since None might just as well
        # be the cached result of a function
        return None
    except Exception:
        logging.warning("[CACHE] Failed to load %s", cache_id)
        return None


def __update_cache(cache_id, content=None):
    stamp_file_path = __get_cache_file_name(cache_id)
    try:
        if content:
            with open(stamp_file_path, "wb") as f:
                pickle.dump(content, f)
        else:
            with open(stamp_file_path, "a"):
                os.utime(stamp_file_path, None)
    except Exception as e:
        logging.warning("[CACHE] Failed to update %s", cache_id, e)
        return

    logging.debug("[CACHE] Stored %s", cache_id)


def cache_func(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not __is_cache_enabled:
            return func(*args, **kwargs)

        args_hash = __simple_args_hash(*args)
        func_name = func.__name__
        module = str(func.__module__).replace(".", "_")
        cache_id = f"{module}_{func_name}_{args_hash}"

        # Return cached value
        if __is_cache_valid(cache_id):
            return __get_cache_content(cache_id)

        cache_content = func(*args, **kwargs)
        __update_cache(cache_id, cache_content)

        return cache_content
    return wrapper


def init_cache(enabled):
    global __is_cache_enabled
    __is_cache_enabled = enabled
