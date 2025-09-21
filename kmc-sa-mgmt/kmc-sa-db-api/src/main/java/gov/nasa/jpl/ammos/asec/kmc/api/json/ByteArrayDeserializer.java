package gov.nasa.jpl.ammos.asec.kmc.api.json;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.io.IOException;

/**
 * Deserializes byte arrays to hex strings for JSON
 */
public class ByteArrayDeserializer extends JsonDeserializer<byte[]> {
    @Override
    public byte[] deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        try {
            return Hex.decodeHex(p.getText());
        } catch (DecoderException e) {
            throw new JsonMappingException(p, "Cannot decode hex", e);
        }
    }
}
