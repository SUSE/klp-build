test:
	python3 -m unittest -v

setup:
	python3 -m unittest -v tests.test_lp_setup.LpSetupTest

ccp:
	python3 -m unittest -v tests.test_ccp.CcpTesting

templ:
	python3 -m unittest -v tests.test_templ.TemplTesting
