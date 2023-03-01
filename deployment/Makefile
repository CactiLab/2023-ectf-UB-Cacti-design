#  2023 eCTF
#  Deployment Makefile
#  Zheyuan Ma
#
#  Copyright (c) 2023 UB Cacti Lab

# function to check required arguments
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1))

all:
	$(call check_defined SECRETS_DIR)
	python3 depl_key_gen.py ${SECRETS_DIR}
