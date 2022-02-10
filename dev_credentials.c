#ifndef __DEV_CREDENTIALS_H__
#define __DEV_CREDENTIALS_H__

#if MBED_CONF_APP_WITH_DTLS && !MBED_CONF_APP_WITH_PSK
#error "Replace dev_credentials.c with your own developer cert."
#endif


#endif //__DEV_CREDENTIALS_H__
