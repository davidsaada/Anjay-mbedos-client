#include "firmware_update.h"

#include <stdio.h>
#include <unistd.h>

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)
#include "fota/fota.h"

static int fw_stream_open(void *user_ptr,
                          const char *package_uri,
                          const struct anjay_etag *package_etag) {
    (void) user_ptr;
    (void) package_uri;
    (void) package_etag;

    return fota_download_start();
}

static int fw_stream_write(void *user_ptr, const void *data, size_t length) {
    (void) user_ptr;
    return fota_download_fragment(data, length);
}

static int fw_stream_finish(void *user_ptr) {
    (void) user_ptr;
    return fota_download_finish();
}

static void fw_reset(void *user_ptr) {
    (void) user_ptr;
    fota_abort();
}

static int fw_perform_upgrade(void *user_ptr) {
    (void) user_ptr;
    return fota_install_firmware();
}

#else // !defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)
static int fw_stream_open(void *user_ptr,
                          const char *package_uri,
                          const struct anjay_etag *package_etag) {
    (void) user_ptr;
    (void) package_uri;
    (void) package_etag;

    printf("fw_stream_open\n");
    return 0;
}

static int fw_stream_write(void *user_ptr, const void *data, size_t length) {
    (void) user_ptr;
    printf("fw_stream_write\n");
    return 0;
}

static int fw_stream_finish(void *user_ptr) {
    (void) user_ptr;
    printf("fw_stream_finish\n");
    return 0;
}

static void fw_reset(void *user_ptr) {
    (void) user_ptr;
    printf("fw_reset\n");
}

static int fw_perform_upgrade(void *user_ptr) {
    (void) user_ptr;
    printf("fw_perform_upgrade\n");
    return 0;
}

#endif // !defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)


static const anjay_fw_update_handlers_t HANDLERS = {
    .stream_open = fw_stream_open,
    .stream_write = fw_stream_write,
    .stream_finish = fw_stream_finish,
    .reset = fw_reset,
    .perform_upgrade = fw_perform_upgrade
};

int fw_update_install(anjay_t *anjay) {
    anjay_fw_update_initial_state_t state;
    int ret;
    memset(&state, 0, sizeof(state));
    state.result = ANJAY_FW_UPDATE_INITIAL_SUCCESS;
    // install the module, pass handlers that we implemented and initial state
    // that we discovered upon startup
#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)
    ret = fota_init();
    if (ret) {
    	return ret;
    }
#endif
    return anjay_fw_update_install(anjay, &HANDLERS, NULL, &state);
}
