#pragma once

#include "esphome/core/component.h"
#include "esphome/components/pn532_sec/pn532_sec.h"
#include "esphome/components/spi/spi.h"

#include <vector>

namespace esphome {
namespace pn532_sec_spi {

class PN532SECSpi : public pn532_sec::PN532SEC,
                 public spi::SPIDevice<spi::BIT_ORDER_LSB_FIRST, spi::CLOCK_POLARITY_LOW, spi::CLOCK_PHASE_LEADING,
                                       spi::DATA_RATE_1MHZ> {
 public:
  void setup() override;

  void dump_config() override;

 protected:
  bool write_data(const std::vector<uint8_t> &data) override;
  bool read_data(std::vector<uint8_t> &data, uint8_t len) override;
  bool read_response(uint8_t command, std::vector<uint8_t> &data) override;
};

}  // namespace pn532_sec_spi
}  // namespace esphome
