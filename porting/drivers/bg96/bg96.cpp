#if defined(BT_01001_V0_1) || defined(BT_01001_V0_2)
#include "mbed.h"
#include "mbed_trace.h"

#include "bg96.h"

#include "QUECTEL_BG96_CellularInformation.h"
#include "CellularDevice.h"
#include "CellularInformation.h"
#include "QUECTEL_BG96.h"

#include "boards.h"
//#include "storage.h"
#include <sstream>

#define BG96_BAUD_RATE 115200       // baud rate for communicating with BG96
#define BG96_WAIT_MS_PWR_KEY_ON 500 // amount of milliseconds to hold power key pin low to turn on BG96
#define BG96_WAIT_MS_PWR_KEY_OFF 650// amount of milliseconds to hold power key pin low to turn off BG96
#define BG96_WAIT_MS_RESET 150      // amount of milliseconds to hold reset pin low to reset BG96

#define TWENTY_FOUR_HOURS_IN_MINS 1440

#define TRACE_GROUP "BG96"

//static Watchdog& watchdog = Watchdog::get_instance();

AquiredLock::AquiredLock(Bg96& bg96, std::atomic<long>& counter) : _bg96(bg96), _lock_counter(counter) {
  _lock_counter++;
}
AquiredLock::~AquiredLock() {
  _lock_counter--;
  _bg96.try_safe_power_off();
}


misc::Synchronized<Bg96, Mutex>* Bg96::get_sync_instance() {
  static misc::Synchronized<Bg96, Mutex>* instance = new misc::Synchronized<Bg96, Mutex>([](){
    auto serial = new UARTSerial(BT_BG96_UART1_TX, BT_BG96_UART1_RX, BG96_BAUD_RATE);
    serial->set_flow_control(SerialBase::RTSCTS, BT_BG96_UART1_RTS, BT_BG96_UART1_CTS);
    return serial;
  }());
  
  return instance;
}

Bg96::Bg96(FileHandle* fh) : QUECTEL_BG96(fh, BT_BG96_PWRKEY, BT_BG96_PIN_ACT_LVL, BT_BG96_RESET),
                             gps_antenna_power(BT_GPS_ACT_ANT_EN, !BT_GPS_ACT_ANT_ACT_LVL),
                             shared_poweron_lock(0) {
}

Bg96::~Bg96() {
}

std::unique_ptr<AquiredLock> Bg96::lock_power_on() {
  return std::make_unique<AquiredLock>(*this, shared_poweron_lock);
}

void Bg96::power_on() {

  if(isPoweredOn) {
    tr_debug("already powered on");
    return;
  }

  //watchdog.kick();

  QUECTEL_BG96::soft_power_on();

  _at->lock();
  _at->flush();
  _at->set_at_timeout(1000);

  _at->at_cmd_discard("&F0", NULL);   // restore AT command settings from NVS
  _at->at_cmd_discard("E0", NULL);    // disable ECHO mode
  _at->at_cmd_discard("+IFC", "=2,2");// enable hardware flow control

  _at->at_cmd_discard("+CMEE", "=2");   // enable error messages
  _at->at_cmd_discard("+CFUN", "=0");   // disable both radios
  _at->at_cmd_discard("+QGPSEND", NULL);// disable gps
  _at->at_cmd_discard("+CTZU", "=1");   // enable automatic timezone updates
  _at->at_cmd_discard("+CTZR", "=2");   // enable extended time zone reporting

  _at->at_cmd_discard("+QCFG", "=\"nwscanseq\",010302,1");         // GSM/NB/M1 - RAT order
  _at->at_cmd_discard("+QCFG", "=\"nwscanmode\",0,1");             // Enable all RATs
  _at->at_cmd_discard("+QCFG", "=\"band\",F,400A0E189F,A0E189F,1");// Any frequncey
  _at->at_cmd_discard("+QCFG", "=\"ledmode\",0");                  // led flicker mode

  _at->restore_at_timeout();
  _at->unlock();
  isPoweredOn = true;

  //watchdog.kick();
}

void Bg96::power_off() {
  tr_info("Bg96::power_off");
  if(!isPoweredOn) {
    // it has to be powered on to send shutdown command to the modem.
    power_on();
  }
  //watchdog.kick();
  shutdown();
  gps_antenna_power = !BT_GPS_ACT_ANT_ACT_LVL;

  ThisThread::sleep_for(2000); // Wait before soft_power_off - this seems to be necessary to correctly shutdown modem
  nsapi_error_t ret = soft_power_off();
  //nsapi_error_t ret = QUECTEL_BG96::soft_power_off();
  //watchdog.kick();

  if(ret != NSAPI_ERROR_OK) {
    tr_error("did not power off module");
    //QUECTEL_BG96::soft_power_off();
    //watchdog.kick();
  }

  isPoweredOn = false;
  isGPSAntennaOn = false;
  isGSMRadioOn = false;
}

void Bg96::try_safe_power_off() {
  if(shared_poweron_lock) {
    tr_debug("Bg96 power is locked. Power off skipped");
    return;
  }
  power_off();
}

bool Bg96::is_powered_on() {
  return isPoweredOn;
}

void Bg96::enable_gsm() {

  if(!isPoweredOn) {
    tr_warn("power must be enabled first");
    return;
  }

  _at->lock();
  _at->flush();
  _at->set_at_timeout(1000);
  _at->at_cmd_discard("+CFUN", "=1");
  _at->restore_at_timeout();
  _at->unlock();

  return;
}

void Bg96::disable_gsm() {
  if(!isPoweredOn) {
    tr_warn("power must be enabled first");
    return;
  }

  _at->lock();
  _at->flush();
  _at->set_at_timeout(15000);
  _at->at_cmd_discard("+CFUN", "=0");
  _at->restore_at_timeout();
  _at->unlock();
  return;
}

void Bg96::enable_gps() {
  if(!isPoweredOn) {
    tr_warn("power must be enabled first");
    return;
  }

  if(isGPSAntennaOn) {
    tr_debug("gps antenna already on");
    return;
  }

  //watchdog.kick();

  gps_antenna_power = BT_GPS_ACT_ANT_ACT_LVL;// enable active antenna

  _at->lock();
  _at->flush();
  _at->set_at_timeout(1000);

  _at->at_cmd_discard("+QGPSCFG", "=\"outport\",\"uartnmea\"");
  _at->at_cmd_discard("+QGPSCFG", "=\"nmeasrc\",1");
  _at->at_cmd_discard("+QGPSCFG", "=\"gpsnmeatype\",31");
  _at->at_cmd_discard("+QGPSCFG", "=\"glonassnmeatype\",4");
  _at->at_cmd_discard("+QGPSCFG", "=\"galileonmeatype\",0");
  _at->at_cmd_discard("+QGPSCFG", "=\"beidounmeatype\",0");
  _at->at_cmd_discard("+QGPSCFG", "=\"gsvextnmeatype\",1");

  _at->at_cmd_discard("+QGPSCFG", "=\"autogps\",0");
  // _at->at_cmd_discard("+QGPSDEL", "=0");// delete assitence data (almanac)
  // _at->at_cmd_discard("+QGPSDEL", "=3");// delete gps extra data

  _at->at_cmd_discard("+QGPSXTRA", "=1");
  _at->cmd_start_stop("+QGPSXTRADATA", "?");// check status of gps extra data
  _at->resp_start("+QGPSXTRADATA:");
  int valid_for = _at->read_int();

  char injection_time[32];
  int read_size = _at->read_string(injection_time, 32);
  tr_debug("gps extra data valid time: %d [min]", valid_for);
  tr_debug("gps extra data injection time: %s", read_size > 0 ? injection_time : "N/A");
#if 0
  if(valid_for < TWENTY_FOUR_HOURS_IN_MINS) {
    tr_warn("gps extra data no longer valid");
    Storage* storage = Storage::get_instance();
    storage->download_gps_extra_save(true);
  } else {
    tr_debug("gps extra data valid for %i more minutes", valid_for);
  }
#endif
  _at->resp_stop();

  _at->at_cmd_discard("+QGPS", "=1");

  _at->restore_at_timeout();
  _at->unlock();

  isGPSAntennaOn = true;

  //watchdog.kick();

  return;
}

bool Bg96::is_gps_enabled() {
  return isGPSAntennaOn;
}

void Bg96::disable_gps() {
  if(!(isGPSAntennaOn && isPoweredOn)) {
    tr_warn("gps antenna and power must be enabled first");
  }

  gps_antenna_power = !BT_GPS_ACT_ANT_ACT_LVL;

  _at->lock();
  _at->flush();
  _at->set_at_timeout(1000);
  _at->at_cmd_discard("+QGPSEND", "");
  _at->restore_at_timeout();
  _at->unlock();

  isGPSAntennaOn = false;

  return;
}

nsapi_error_t Bg96::get_sim_iccid(char* sim_iccid, size_t buf_size) {
  _at->lock();
  mbed::QUECTEL_BG96_CellularInformation cellular_information(*_at);
  nsapi_error_t error = cellular_information.get_iccid(sim_iccid, buf_size);
  _at->unlock();
  return error;
}

bool Bg96::gps_lock(char* gps_lock) {
  if(!(isGPSAntennaOn && isPoweredOn)) {
    tr_warn("gps antenna and power must be enabled first");
    return false;
  }

  _at->lock();
  _at->flush();
  _at->set_at_timeout(1000);
  _at->set_stop_tag("\r\n");

  _at->cmd_start_stop("+QGPSLOC", "=2");

  _at->resp_start("+QGPSLOC: ");
  if(_at->info_resp()) {
    _at->set_delimiter(':');
    _at->read_string(gps_lock, BG96_GPS_LOCK_SIZE);
    _at->set_default_delimiter();
  }
  _at->resp_stop();

  nsapi_error_t error = _at->get_last_error();

  _at->restore_at_timeout();
  _at->unlock();

  return (error == NSAPI_ERROR_OK);
}
#if 0
nsapi_error_t Bg96::download_file_gps_extra_data(void) {
  if(!isPoweredOn) {
    tr_warn("power must be enabled first");
    return NSAPI_ERROR_DEVICE_ERROR;
  }

  //watchdog.kick();

  bool download_complete = false;

  _at->lock();
  _at->flush();

  _at->set_at_timeout(3000);
  _at->cmd_start_stop("+QHTTPURL", "=40,3", NULL);
  _at->resp_start("CONNECT");
  _at->write_string("http://xtrapath1.izatcloud.net/xtra2.bin", false);
  _at->resp_stop();

  _at->set_at_timeout(80000);
  _at->at_cmd_discard("+QHTTPGET", "=80", NULL);

  _at->resp_start("+QHTTPGET:");
  if(_at->info_resp()) {
    int http_get_error = _at->read_int();
    int http_status_ret = _at->read_int();
    size_t gps_data_size = _at->read_int();
    tr_info("gps extra data, error: %i, https status: %i, size: %i", http_get_error, http_status_ret, gps_data_size);
    download_complete = (http_status_ret == 200);
  } else {
    tr_error("downloading gps extra data");
  }

  nsapi_error_t error = _at->get_last_error();

  if(download_complete) {
    _at->at_cmd_discard("+QHTTPREADFILE", "=", "%s,%d", "xtra2.bin", 80);
    _at->resp_start("+QHTTPREADFILE:");
    _at->info_resp();
    int load_file_status = _at->read_int();
    tr_info("load file status %i", load_file_status);

    time_t current_time = time(NULL);
    struct tm* inject_time = gmtime(&current_time);
    char bg96_extra_inject_ts[22];
    strftime(bg96_extra_inject_ts, 22, "%G/%m/%d,%H:%M:%S", inject_time);
    // before xdata injection we have to disable gps
    _at->at_cmd_discard("+QGPSEND", NULL);

    _at->at_cmd_discard("+QGPSXTRA", "=1", NULL);
    _at->at_cmd_discard("+QGPSXTRATIME", "=", "%d,%s,%d,%d,%d", 0, bg96_extra_inject_ts, 1, 0, 5000);
    _at->at_cmd_discard("+QGPSXTRADATA", "=", "%s", "UFS:xtra2.bin");
    _at->at_cmd_discard("+QFDEL", "=", "%s", "UFS:xtra2.bin");
    _at->at_cmd_discard("+QGPS", "=1");
    Storage* storage = Storage::get_instance();
    storage->download_gps_extra_save(false);
  }

  _at->restore_at_timeout();
  _at->unlock();

  //watchdog.kick();

  return error;
}
#endif
nsapi_error_t Bg96::soft_power_off() {
  _at->lock();
  _at->cmd_start("AT+QPOWD");
  _at->cmd_stop_read_resp();

  return _at->unlock_return_error();
}

nsapi_error_t Bg96::configure_dns(void) {
  _at->lock();
  _at->at_cmd_discard("+QIDNSCFG", "=", "%d", 1);
  _at->at_cmd_discard("+QIDNSCFG", "=", "%d,%s,%s", 1, "8.8.8.8", "8.8.4.4");
  _at->at_cmd_discard("+QIGETERROR", "", "");
  return _at->unlock_return_error();
}

CellularDevice* CellularDevice::get_default_instance() {
  return Bg96::get_sync_instance()->non_sync_block([](auto& bg96) {
    return static_cast<CellularDevice*>(&bg96);
  });
}
#endif // #if defined(BT_01001_V0_1) || defined(BT_01001_V0_2)

