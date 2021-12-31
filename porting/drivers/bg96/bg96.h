#ifndef BG96_H
#define BG96_H

#include "QUECTEL_BG96.h"
#include "mbed.h"
#include "platform/NonCopyable.h"
#include "Synchronized.h"
#include <memory>
#include <atomic>


#define BG96_GPS_LOCK_SIZE 70

typedef struct hardware_info_t {
  char model[5];
  char rev[32];
  char imei[16];
  char iccid[20];
} hardware_info;

class AquiredLock;

/**
 * @brief LTE and GPS modem class.
 */
class Bg96 : public QUECTEL_BG96, private NonCopyable<Bg96>
{
public:
  static misc::Synchronized<Bg96, Mutex>* get_sync_instance();
  /**
   * @brief power on the modem. Does not care about power lock
   */
  void power_on();
  /**
   * @brief Creates an AquiredLock for the BG96 modem power switch.
   *        As long as the returned lock instance is alive, the lock counter will no decrement
   * @return unique_ptr to lock instance
   */
  std::unique_ptr<AquiredLock> lock_power_on();
  /**
   * @brief power off the modem. Does not care about power lock
   */
  void power_off();
  /**
   * @brief power off the modem only if power lock is released
   */
  void try_safe_power_off();
  bool is_powered_on();
  void enable_gsm();
  void disable_gsm();
  void enable_gps();
  bool is_gps_enabled();
  void disable_gps();
  nsapi_error_t get_sim_iccid(char* sim_iccid, size_t buf_size);
  bool gps_lock(char* gps_lock);
  nsapi_error_t soft_power_off();
  //nsapi_error_t download_file_gps_extra_data(void);
  nsapi_error_t configure_dns(void);

  ~Bg96();

private:
  Bg96(FileHandle* fh);

  DigitalOut gps_antenna_power;

  UARTSerial* serial_connection;

  bool isPoweredOn;
  bool isGPSAntennaOn;
  bool isGSMRadioOn;
  std::atomic<long> shared_poweron_lock;

  friend class QUECTEL_BG96;
  friend class CellularDevice;
};

using SynchronizedBg96 = misc::Synchronized<Bg96, Mutex>;

/**
 * @brief Synchronization class for Bg96. Bg96 is a two-in-one device, a GPS and LTE modem.
 *        Transmission and Location modules are both using the same devie but in different context, hence
 *        some of the actions will overlap or will be mutually exclusive, such as powering the modem off.
 *        Every created instance of the AquiredLock will increment the lock_counter (passed by constructor).
 *        Every deleted instance will decremented the counter.
 *        A lock is considered released when counter is equal to 0.
 */
class AquiredLock {
  Bg96& _bg96;
  std::atomic<long>& _lock_counter;
public:
  /**
   * @brief Constructor
   * @param bg96 BG96 driver
   * @param counter users counter. Stored in the BG96 driver.
   */
  AquiredLock(Bg96& bg96, std::atomic<long>& counter);
  ~AquiredLock();
};

#endif// BG96_H