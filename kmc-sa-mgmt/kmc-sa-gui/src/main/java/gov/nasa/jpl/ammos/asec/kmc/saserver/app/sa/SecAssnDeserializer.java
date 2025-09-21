package gov.nasa.jpl.ammos.asec.kmc.saserver.app.sa;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.fasterxml.jackson.databind.node.ObjectNode;
import gov.nasa.jpl.ammos.asec.kmc.api.sa.FrameType;
import gov.nasa.jpl.ammos.asec.kmc.api.sa.ISecAssn;

import java.io.IOException;

public class SecAssnDeserializer extends JsonDeserializer<ISecAssn> {
    private static ObjectMapper M;

    static {
        M = new ObjectMapper();
        M.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    @Override
    public ISecAssn deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JacksonException {
        ObjectNode root = p.readValueAs(ObjectNode.class);
        FrameType  type;
        if (root.has("type")) {
            type = FrameType.fromString(root.get("type").asText());
            if (type == FrameType.UNKNOWN) {
                throw new InvalidFormatException(p, String.format("Frame type %s is invalid",
                        root.get("type").asText()), root, ISecAssn.class);
            }
        } else {
            type = FrameType.TC;
        }
        return M.convertValue(root, type.getClazz());
    }
}
