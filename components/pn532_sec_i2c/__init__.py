import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import i2c, pn532_sec
from esphome.const import CONF_ID

AUTO_LOAD = ["pn532_sec"]
CODEOWNERS = ["@OttoWinter", "@jesserockz"]
DEPENDENCIES = ["i2c"]

pn532_sec_i2c_ns = cg.esphome_ns.namespace("pn532_sec_i2c")
PN532SECI2C = pn532_sec_i2c_ns.class_("PN532SECI2C", pn532_sec.PN532SEC, i2c.I2CDevice)

CONFIG_SCHEMA = cv.All(
    pn532_sec.PN532SEC_SCHEMA.extend(
        {
            cv.GenerateID(): cv.declare_id(PN532SECI2C),
        }
    ).extend(i2c.i2c_device_schema(0x24))
)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await pn532_sec.setup_pn532_sec(var, config)
    await i2c.register_i2c_device(var, config)
