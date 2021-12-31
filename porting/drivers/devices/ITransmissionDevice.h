#ifndef BTTM_TASKS_ITRANSMISSIONDEVICE_H_INCLUDED
#define BTTM_TASKS_ITRANSMISSIONDEVICE_H_INCLUDED

class NetworkInterface;

namespace tasks {
class ITransmissionDevice
{
public:
  virtual bool enable() = 0;
  virtual bool disable() = 0;
  //virtual void download_gps_extra_data() = 0;
  virtual NetworkInterface* get_network_interface() = 0;

  virtual ~ITransmissionDevice() {}
};

}// namespace tasks

#endif
