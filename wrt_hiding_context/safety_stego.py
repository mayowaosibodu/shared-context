# safety_stego.py
import json

class SafetyStego:
    # Zero-width chars
    ZW_HEADER = "\u200B"
    ZW0 = "\u200C"
    ZW1 = "\u200D"

    def serialize(self, obj: dict) -> str:
        return json.dumps(obj)

    def deserialize(self, s: str):
        try:
            return json.loads(s)
        except:
            return None

    # --------------------------------------------
    # Bit helpers
    # --------------------------------------------
    def string_to_bits(self, s: str):
        return "".join(f"{ord(ch):08b}" for ch in s)

    def bits_to_string(self, bits: str):
        chars = []
        for i in range(0, len(bits), 8):
            chunk = bits[i:i+8]
            if len(chunk) == 8:
                chars.append(chr(int(chunk, 2)))
        return "".join(chars)

    # --------------------------------------------
    # Zero-width encoding
    # --------------------------------------------
    def bits_to_zw(self, bits: str):
        return "".join(self.ZW1 if b == "1" else self.ZW0 for b in bits)

    def zw_to_bits(self, payload: str):
        return "".join("1" if ch == self.ZW1 else "0" for ch in payload if ch in (self.ZW0, self.ZW1))

    # --------------------------------------------
    # Public API: embed/extract
    # --------------------------------------------
    def embed(self, visible_text: str, safety_state: dict) -> str:
        serialized = self.serialize(safety_state)
        bits = self.string_to_bits(serialized)
        hidden = self.bits_to_zw(bits)
        return visible_text + self.ZW_HEADER + hidden

    def extract(self, text: str):
        if self.ZW_HEADER not in text:
            return None

        _, payload = text.split(self.ZW_HEADER, 1)
        bits = self.zw_to_bits(payload)
        decoded = self.bits_to_string(bits)
        return self.deserialize(decoded)
