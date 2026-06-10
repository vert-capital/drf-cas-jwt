SHELL:=/bin/bash
TRIVY_IMAGE ?= aquasec/trivy:0.69.3

chown_project:
	sudo chown -R "${USER}:${USER}" ./


security-scan: chown_project
	find . -name "__pycache__" -type d -exec rm -rf {} +
	docker run --rm \
		-v $(PWD):/project \
		-v trivy-cache:/root/.cache/trivy \
		$(TRIVY_IMAGE) fs \
		--scanners vuln,secret,misconfig \
		--exit-code 0 \
		--include-dev-deps \
		--severity HIGH,CRITICAL,MEDIUM \
		--skip-dirs dist/ \
		/project/