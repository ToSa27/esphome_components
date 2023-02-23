import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import spi, pn532_sec
from esphome.const import CONF_ID

AUTO_LOAD = ["pn532_sec"]
CODEOWNERS = ["@OttoWinter", "@jesserockz"]
DEPENDENCIES = ["spi"]
MULTI_CONF = True

pn532_sec_spi_ns = cg.esphome_ns.namespace("pn532_sec_spi")
PN532SECSpi = pn532_sec_spi_ns.class_("PN532SECSpi", pn532_sec.PN532SEC, spi.SPIDevice)

CONFIG_SCHEMA = cv.All(
    pn532_sec.PN532SEC_SCHEMA.extend(
        {
            cv.GenerateID(): cv.declare_id(PN532SECSpi),
        }
    ).extend(spi.spi_device_schema(cs_pin_required=True))
)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await pn532_sec.setup_pn532_sec(var, config)
    await spi.register_spi_device(var, config)
