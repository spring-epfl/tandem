add_executable(test-paillier
  test-paillier.c)
set_target_properties(test-paillier PROPERTIES INSTALL_RPATH ${TANDEM_INSTALL_LIB_DIR})
target_link_libraries(test-paillier gmp paillier)
install(TARGETS test-paillier DESTINATION ${TANDEM_INSTALL_BIN_DIR})

add_executable(test-bbsplus
  test-bbsplus.c
  $<TARGET_OBJECTS:bbsplus>
  $<TARGET_OBJECTS:utils>)
target_link_libraries(test-bbsplus ${RELIC} ${OPENSSL_LIBRARIES} gmp sodium)
install(TARGETS test-bbsplus DESTINATION ${TANDEM_INSTALL_BIN_DIR})

add_executable(test-commit
  test-commit.c
  $<TARGET_OBJECTS:commit>)
target_link_libraries(test-commit ${RELIC} gmp)
install(TARGETS test-commit DESTINATION ${TANDEM_INSTALL_BIN_DIR})

add_executable(test-tandem
  test-tandem.c
  $<TARGET_OBJECTS:bbsplus>
  $<TARGET_OBJECTS:commit>
  $<TARGET_OBJECTS:utils>
  $<TARGET_OBJECTS:tandem>)
target_link_libraries(test-tandem ${RELIC} ${OPENSSL_LIBRARIES} gmp sodium homenc)
install(TARGETS test-tandem DESTINATION ${TANDEM_INSTALL_BIN_DIR})

add_executable(test-openssl test-openssl.c)
target_link_libraries(test-openssl ${OPENSSL_LIBRARIES} gmp sodium m)
install(TARGETS test-openssl DESTINATION ${TANDEM_INSTALL_BIN_DIR})

add_executable(test-homenc test-homenc.c)
target_link_libraries(test-homenc gmp sodium m homenc)
install(TARGETS test-homenc DESTINATION ${TANDEM_INSTALL_BIN_DIR})
