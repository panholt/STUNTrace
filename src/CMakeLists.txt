#
#
# nptrace, network path trace


set (ADDITIONAL_LIBS "")

#find_package( OpenSSL )
#if( OPENSSL_FOUND )
#  include_directories( ${OPENSSL_INCLUDE_DIR} )
#  list(APPEND ADDITIONAL_LIBS ${OPENSSL_LIBRARIES})
#endif( OPENSSL_FOUND )

add_executable ( nptrace
                 iphelper.c
                 sockethelper.c
                 ip_query.c
                 utils.c
                 nptrace.c )

target_link_libraries ( nptrace PRIVATE pa
                        sockaddrutil
                        stunlib
                        pthread
                        ${ADDITIONAL_LIBS})

set_target_properties(nptrace PROPERTIES INSTALL_RPATH "${install_dir}/lib")
set_target_properties(nptrace PROPERTIES BUILD_WITH_INSTALL_RPATH ON)

include_directories ( ../include )
link_directories ( ${CHECK_LIBRARY_DIRS} )

set (crusty_files
     nptrace.c
     iphelper.c
     sockethelper.c)

UncrustifyDir(crusty_files)
