test: @node node_modules/lab/bin/lab
test-cov: @node node_modules/lab/bin/lab -t 100
test-cov-html: @node node_modules/lab/bin/lag -r html -o coverage.html
.PHONY: test test-cov test-cov-html