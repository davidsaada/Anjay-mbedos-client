#include "TransmissionDeviceBG96.h"
#include "CellularContext.h"

namespace tasks {
TransmissionDeviceBG96::TransmissionDeviceBG96(SynchronizedBg96& driver)
: m_bg96{driver} {

}

bool TransmissionDeviceBG96::enable() {
  m_bg96.sync_block([this](auto& bg96) {
    m_power_lock = bg96.lock_power_on();
    if(!bg96.is_powered_on()) {
      bg96.power_on();
    }

    bg96.enable_gsm();
  });

  return true;
}

bool TransmissionDeviceBG96::disable() {
  m_bg96.sync_block([this](auto& bg96) {
    if(bg96.is_powered_on()) {
      bg96.disable_gsm();
    }

    m_power_lock = nullptr;
  });
  return true;
}
#if 0
void TransmissionDeviceBG96::download_gps_extra_data() {
  m_bg96.sync_block([this](auto& bg96) {
    bg96.download_file_gps_extra_data();
  });
}
#endif
NetworkInterface* TransmissionDeviceBG96::get_network_interface() {
  return CellularContext::get_default_instance();
}

} // namespace tasks