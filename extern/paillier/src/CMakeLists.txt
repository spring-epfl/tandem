add_library(paillier SHARED paillier.c)
install(TARGETS paillier DESTINATION ${TANDEM_INSTALL_LIB_DIR})
