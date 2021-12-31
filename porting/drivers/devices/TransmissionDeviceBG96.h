
#ifndef BTTM_TRANSMISSIONDEVICEBG96_H_INCLUDED
#define BTTM_TRANSMISSIONDEVICEBG96_H_INCLUDED
#include "ITransmissionDevice.h"
#include "bg96.h"
#include <memory>

namespace tasks {

class TransmissionDeviceBG96 : public ITransmissionDevice {
public:
  TransmissionDeviceBG96(SynchronizedBg96& driver);
  virtual bool enable() override;
  virtual bool disable() override;
  //virtual void download_gps_extra_data() override;
  virtual NetworkInterface* get_network_interface() override;
private:
  SynchronizedBg96& m_bg96;
  std::unique_ptr<AquiredLock> m_power_lock;
};
} // namespace tasks

#endif // BTTM_TRANSMISSIONDEVICE_H_INCLUDED
