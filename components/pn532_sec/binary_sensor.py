import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import binary_sensor
from esphome.const import CONF_UID
from esphome.core import HexInt
from . import pn532_sec_ns, PN532SEC, CONF_PN532SEC_ID

DEPENDENCIES = ["pn532_sec"]


def validate_uid(value):
    value = cv.string_strict(value)
    for x in value.split("-"):
        if len(x) != 2:
            raise cv.Invalid(
                "Each part (separated by '-') of the UID must be two characters "
                "long."
            )
        try:
            x = int(x, 16)
        except ValueError as err:
            raise cv.Invalid(
                "Valid characters for parts of a UID are 0123456789ABCDEF."
            ) from err
        if x < 0 or x > 255:
            raise cv.Invalid(
                "Valid values for UID parts (separated by '-') are 00 to FF"
            )
    return value


PN532SECBinarySensor = pn532_sec_ns.class_("PN532SECBinarySensor", binary_sensor.BinarySensor)

CONFIG_SCHEMA = binary_sensor.binary_sensor_schema(PN532SECBinarySensor).extend(
    {
        cv.GenerateID(CONF_PN532SEC_ID): cv.use_id(PN532SEC),
        cv.Required(CONF_UID): validate_uid,
    }
)


async def to_code(config):
    var = await binary_sensor.new_binary_sensor(config)

    hub = await cg.get_variable(config[CONF_PN532SEC_ID])
    cg.add(hub.register_tag(var))
    addr = [HexInt(int(x, 16)) for x in config[CONF_UID].split("-")]
    cg.add(var.set_uid(addr))
