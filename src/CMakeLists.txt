add_library(bbsplus OBJECT bbsplus.c)

add_library(commit OBJECT commit.c)

add_library(homenc homenc.c)
target_link_libraries(homenc bhjl)

add_library(tandem OBJECT tandem.c)

add_library(utils OBJECT utils.c)
