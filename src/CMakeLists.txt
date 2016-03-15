#
#
# stuntrace, network path trace


set (ADDITIONAL_LIBS "")

if(NOT APPLE)
 list(APPEND ADDITIONAL_LIBS "uuid")
endif()

#find_package( OpenSSL )
#if( OPENSSL_FOUND )
#  include_directories( ${OPENSSL_INCLUDE_DIR} )
#  list(APPEND ADDITIONAL_LIBS ${OPENSSL_LIBRARIES})
#endif( OPENSSL_FOUND )



add_executable ( stuntrace
                 ${version_file}
                 iphelper.c
                 sockethelper.c
                 ip_query.c
                 utils.c
                 stuntrace.c )

target_link_libraries ( stuntrace PRIVATE pa
                        sockaddrutil
                        stunlib
                        pthread
                        cassandra
                        ${ADDITIONAL_LIBS})

set_target_properties(stuntrace PROPERTIES INSTALL_RPATH "${install_dir}/lib")
set_target_properties(stuntrace PROPERTIES BUILD_WITH_INSTALL_RPATH ON)

include_directories ( ../include )
link_directories ( ${CHECK_LIBRARY_DIRS} )

set (crusty_files
     stuntrace.c
     iphelper.c
     sockethelper.c)

UncrustifyDir(crusty_files)
