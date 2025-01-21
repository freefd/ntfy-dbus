SHELL := /usr/bin/env bash
SRC_DIR := ${CURDIR}/src

SYSTEMD_SERVICE_FILES := $(wildcard $(SRC_DIR)/*.service)
SYSTEMD_TIMER_FILES := $(wildcard $(SRC_DIR)/*.timer)
PYTHON_FILES := $(wildcard $(SRC_DIR)/*.py)

USER_SYSTEMD_DIRECTORY := ${HOME}/.config/systemd/user
USER_LOCALBIN_DIRECTORY := ${HOME}/.local/bin
USER_LOCALCONFIG_DIRECTORY := ${HOME}/.config/ntfy-dbus

EXECUTABLES = python3 systemctl sed column tput install ls rm

LOGGING_FUNCTION = @echo "--- ${1}"
.DEFAULT_GOAL := help
.PHONY: help install uninstall clean

check:
	$(call LOGGING_FUNCTION, Check prerequisites)
	$(foreach exec, ${EXECUTABLES}, $(if $(shell command -v $(exec) 2>/dev/null), \
		, $(error [!] $(exec) util not found in $$PATH)))
	@echo "[=] All prerequisites have been met"
	@echo

install: enable_systemctl reload_systemctl_daemon readme ## Install systemd user files, create dummy configuration, copy executable and run
uninstall: uninstall_python_files reload_systemctl_daemon ## Uninstall systemd files, delete executable, preserve the configuration

create_directories: check
	$(call LOGGING_FUNCTION,Create directories if necessary)
	@for dir in ${USER_LOCALCONFIG_DIRECTORY}; do \
		if [[ ! -d "$$dir" ]]; then \
			echo "[+] $$dir"; \
			mkdir $$dir; \
		fi; \
	done
	@echo

create_configuration: create_directories
	$(call LOGGING_FUNCTION,Create dummy configuration)
	@if [[ ! -f "${USER_LOCALCONFIG_DIRECTORY}/config" ]]; then \
		echo "[+] ${USER_LOCALCONFIG_DIRECTORY}/config"; \
		touch "${USER_LOCALCONFIG_DIRECTORY}/config"; \
		echo -ne "NTFY_DBUS_TOKEN=\nNTFY_DBUS_SERVER=ntfy.sh\nNTFY_DBUS_TOPIC=test\nNTFY_DBUS_APPEND_URL=false\n" > "${USER_LOCALCONFIG_DIRECTORY}/config"; \
	fi;
	@echo
	
install_systemd_files: create_configuration
	$(call LOGGING_FUNCTION,Install systemd files)
	@for file in ${SYSTEMD_SERVICE_FILES} ${SYSTEMD_TIMER_FILES}; do \
		echo "[+] $$(basename $$file)"; \
		install -m 0644 -D -v $$file -t ${USER_SYSTEMD_DIRECTORY}; \
	done
	@echo

install_python_files: install_systemd_files
	$(call LOGGING_FUNCTION,Install python files)
	@for file in ${PYTHON_FILES}; do \
		echo "[+] $$(basename $$file) "; \
		install -m 0755 -D -v $$file -t ${USER_LOCALBIN_DIRECTORY}; \
	done
	@echo

enable_systemctl: install_python_files
	$(call LOGGING_FUNCTION,Enable systemd services and timers)
	@for file in ${SYSTEMD_SERVICE_FILES} ${SYSTEMD_TIMER_FILES}; do \
		if ! [[ "$$file" =~ '@' ]]; then \
			echo "[*] $$(basename $$file)"; \
			systemctl --user enable --now $$(basename $$file); \
		fi; \
	done
	@echo

disable_systemctl: check
	$(call LOGGING_FUNCTION,Disable systemd services)
	@-for file_name in ${SYSTEMD_SERVICE_FILES} ${SYSTEMD_TIMER_FILES}; do \
		if ! [[ "$$file_name" =~ '@' ]] ; then \
			echo "[-] $$(basename $$file_name)"; \
			systemctl --user disable --now $$(basename $$file_name) 2>/dev/null; \
		fi; \
	done
	@echo

reload_systemctl_daemon:
	$(call LOGGING_FUNCTION,Reload systemd daemon)
	@systemctl --user daemon-reload
	@echo

uninstall_systemd_files: disable_systemctl
	$(call LOGGING_FUNCTION,Uninstall systemd files)
	@for file in ${PYTHON_FILES} ${SYSTEMD_SERVICE_FILES} ${SYSTEMD_TIMER_FILES}; do \
		if [[ -f "${USER_SYSTEMD_DIRECTORY}/$$(basename $$file)" ]]; then \
			echo "[-] ${USER_SYSTEMD_DIRECTORY}/$$(basename $$file)"; \
			rm "${USER_SYSTEMD_DIRECTORY}/$$(basename $$file)"; \
		fi; \
	done
	@echo

uninstall_python_files: uninstall_systemd_files
	$(call LOGGING_FUNCTION,Uninstall python files)
	@-for file in ${PYTHON_FILES}; do \
		if [[ -f "${USER_LOCALBIN_DIRECTORY}/$$(basename $$file)" ]]; then \
			echo "[-] ${USER_LOCALBIN_DIRECTORY}/$$(basename $$file)"; \
			rm -f "${USER_LOCALBIN_DIRECTORY}/$$(basename $$file)"; \
		fi; \
	done
	@echo

readme: ## README, how to configure
	$(call LOGGING_FUNCTION,Readme)
	@echo 'Please follow to https://github.com/freefd/articles/9_ntfy_and_dbus_integration/'
	@gio open https://github.com/freefd/articles/9_ntfy_and_dbus_integration/ 2>/dev/null || xdg-open https://github.com/freefd/articles/9_ntfy_and_dbus_integration/ 2>/dev/null

help: ## Show all usable commands
	@sed -e '/^[a-zA-Z0-9_\-]*:.*\#\#/!d' -e 's/:.*\#\#\s*/:/' \
		-e 's/^\(.\+\):\(.*\)/$(shell tput setaf 6)\1$(shell tput sgr0):\2/' $(MAKEFILE_LIST) | column -c2 -t -s :
	@echo
