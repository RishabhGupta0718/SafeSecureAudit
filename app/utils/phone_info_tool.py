import phonenumbers
from phonenumbers import geocoder, carrier

def gather_phone_info(phone_number):
    try:
        parsed_number = phonenumbers.parse(phone_number, None)
        if not phonenumbers.is_valid_number(parsed_number):
            return "Invalid phone number."

        country = geocoder.country_name_for_number(parsed_number, "en")
        carrier_name = carrier.name_for_number(parsed_number, "en")
        return {
            'phone_number': phone_number,
            'country': country,
            'carrier': carrier_name
        }

    except phonenumbers.phonenumberutil.NumberParseException as e:
        return "Error parsing phone number:", e
