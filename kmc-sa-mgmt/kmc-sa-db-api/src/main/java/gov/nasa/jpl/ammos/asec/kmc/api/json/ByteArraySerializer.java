package gov.nasa.jpl.ammos.asec.kmc.api.json;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import org.apache.commons.codec.binary.Hex;

import java.io.IOException;

/**
 * Serializes byte arrays to hex strings for JSON
 */
public class ByteArraySerializer extends JsonSerializer<byte[]> {

    @Override
    public void serialize(byte[] value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
        gen.writeObject(Hex.encodeHexString(value));
    }
}
