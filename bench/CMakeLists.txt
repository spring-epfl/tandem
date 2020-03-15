add_executable(bench-paillier
  bench-paillier.c)
set_target_properties(bench-paillier PROPERTIES INSTALL_RPATH ${TANDEM_INSTALL_LIB_DIR})
target_link_libraries(bench-paillier gmp paillier)
install(TARGETS bench-paillier DESTINATION ${TANDEM_INSTALL_BIN_DIR})

add_executable(bench-tandem
  bench-tandem.c
  $<TARGET_OBJECTS:bbsplus>
  $<TARGET_OBJECTS:commit>
  $<TARGET_OBJECTS:utils>
  $<TARGET_OBJECTS:tandem>)
target_link_libraries(bench-tandem ${RELIC} ${OPENSSL_LIBRARIES} gmp sodium m homenc)
install(TARGETS bench-tandem DESTINATION ${TANDEM_INSTALL_BIN_DIR})

add_executable(bench-homenc
  bench-homenc.c)
target_link_libraries(bench-homenc gmp sodium m homenc)
install(TARGETS bench-homenc DESTINATION ${TANDEM_INSTALL_BIN_DIR})

add_executable(bench-primitives
  bench-primitives.c)
target_link_libraries(bench-primitives ${RELIC} gmp)
install(TARGETS bench-primitives DESTINATION ${TANDEM_INSTALL_BIN_DIR})
