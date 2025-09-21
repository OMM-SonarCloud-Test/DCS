package gov.nasa.jpl.ammos.asec.kmc.api.json;

import com.fasterxml.jackson.core.JsonGenerator;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class ByteArraySerializerTest {

    @Test
    public void testSerialize() throws IOException {
        JsonGenerator gen = mock(JsonGenerator.class);

        String want = "01020304";
        want.intern();
        ByteArraySerializer serializer = new ByteArraySerializer();
        serializer.serialize(new byte[]{0x01, 0x02, 0x03, 0x04}, gen, null);
        ArgumentCaptor<String> arg = ArgumentCaptor.forClass(String.class);
        verify(gen).writeObject(want);
        verify(gen).writeObject(arg.capture());
        assertEquals(want, arg.getValue());
    }

}