package gov.nasa.jpl.ammos.asec.kmc.saserver.app.sa;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import gov.nasa.jpl.ammos.asec.kmc.api.ex.KmcException;
import gov.nasa.jpl.ammos.asec.kmc.api.sa.FrameType;
import gov.nasa.jpl.ammos.asec.kmc.api.sa.ISecAssn;
import gov.nasa.jpl.ammos.asec.kmc.api.sa.ServiceType;
import gov.nasa.jpl.ammos.asec.kmc.api.sa.SpiScid;
import gov.nasa.jpl.ammos.asec.kmc.sadb.BaseH2Test;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class SaControllerTest extends BaseH2Test {

    @Autowired
    private SaController sa;

    private ObjectMapper mapper = new ObjectMapper();

    @Test
    public void contextLoads() {
        assertNotNull(sa);
    }

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    public void testGetSas() {
        ArrayNode resp = restTemplate.getForObject(getUrl(), ArrayNode.class);
        assertNotNull(resp);
        assertEquals(15, resp.size());
    }

    @Test
    public void testGetSasByType() {
        testGetSasByType("tc");
        testGetSasByType("tm");
        testGetSasByType("aos");

    }

    private void testGetSasByType(String type) {
        ArrayNode resp = restTemplate.getForObject(getUrl() + "/" + type, ArrayNode.class);
        assertNotNull(resp);
        assertEquals(5, resp.size());
    }

    private String getUrl() {
        return String.format("http://localhost:%d/api/sa", port);
    }


    private ObjectNode createSaJson() {
        ObjectNode node = mapper.createObjectNode();
        node.withObject("/id").put("spi", 100).put("scid", 46);
        node.put("tfvn", 0).put("vcid", 20).put("mapid", 0).put("ekid", "kmc/test/key128").putNull(
                "akid").put("saState", 3).putNull("lpid").put("est", 1).put("ast", 1).put("shivfLen", 12).put(
                "shsnfLen", 0).put("shplfLen", 0).put("stmacfLen", 16).put("ecsLen", 1).put("ecs", "01").put(
                "ivLen", 12).put("iv", "000000000000000000000001").put("acsLen", 1).put("acs", "00").put("abmLen",
                19).put("abm", "ffffffffffffff000000000000000000000000").put("arsnLen", 0).put("arsn", "").put("arsnw"
                , 5).put("spi", 100).put("scid", 46).put("serviceType", "AUTHENTICATED_ENCRYPTION");
        return node;
    }

    @Test
    public void testCreateSaByType() throws KmcException {
        createSaByType(FrameType.TC);
        createSaByType(FrameType.TM);
        createSaByType(FrameType.AOS);
    }

    public void createSaByType(FrameType type) throws KmcException {
        ObjectNode node = createSaJson();
        node.put("type", type.name());
        HttpEntity<JsonNode> req = new HttpEntity<>(node);

        ResponseEntity<ObjectNode> resp = restTemplate.exchange(getUrl(),
                HttpMethod.PUT, req, ObjectNode.class, new Object[0]);
        assertNotNull(resp);
        ObjectNode body       = resp.getBody();
        JsonNode   statusNode = body.get("status");
        if (statusNode != null) {
            String status = statusNode.asText();
            assertNotEquals("error", status);
        }
        assertEquals(100, body.get("spi").asInt());
        assertEquals(46, body.get("scid").asInt());

        ISecAssn created = dao.getSa(new SpiScid(100, (short) 46), type);
        assertNotNull(created);
        assertArrayEquals(new byte[]{0x00}, created.getAcs());
        assertArrayEquals(new byte[]{(byte) 0xff,
                (byte) 0xff,
                (byte) 0xff,
                (byte) 0xff,
                (byte) 0xff,
                (byte) 0xff,
                (byte) 0xff,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00}, created.getAbm());
        assertArrayEquals(new byte[]{0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x01}, created.getIv());
        assertEquals(type, created.getType());
    }

    @Test
    public void testCreateSa() throws KmcException {
        ObjectNode           node = createSaJson();
        HttpEntity<JsonNode> req  = new HttpEntity<>(node);

        ResponseEntity<ObjectNode> resp = restTemplate.exchange(getUrl(),
                HttpMethod.PUT, req, ObjectNode.class, new Object[0]);
        assertNotNull(resp);
        ObjectNode body       = resp.getBody();
        JsonNode   statusNode = body.get("status");
        if (statusNode != null) {
            String status = statusNode.asText();
            assertNotEquals("error", status);
        }
        assertEquals(100, body.get("spi").asInt());
        assertEquals(46, body.get("scid").asInt());

        ISecAssn created = dao.getSa(new SpiScid(100, (short) 46), FrameType.TC);
        assertNotNull(created);
        assertArrayEquals(new byte[]{0x00}, created.getAcs());
        assertArrayEquals(new byte[]{(byte) 0xff,
                (byte) 0xff,
                (byte) 0xff,
                (byte) 0xff,
                (byte) 0xff,
                (byte) 0xff,
                (byte) 0xff,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00}, created.getAbm());
        assertArrayEquals(new byte[]{0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x01}, created.getIv());
    }

    @Test
    public void testUpdateSaByType() throws KmcException {
        updateSaByType(FrameType.TC);
        updateSaByType(FrameType.TM);
        updateSaByType(FrameType.AOS);
    }

    public void updateSaByType(FrameType type) throws KmcException {
        createSaByType(type);
        ObjectNode node = createSaJson();
        node.put("type", type.name());
        node.put("tfvn", 1).put("est", 0).put("ast", 0).put("serviceType", "PLAINTEXT");

        ObjectNode body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);

        assertEquals(1, body.get("tfvn").asInt());
        assertEquals("PLAINTEXT", body.get("serviceType").asText());
        assertEquals(0, body.get("est").asInt());
        assertEquals(0, body.get("ast").asInt());
        assertEquals(type.name(), body.get("type").asText());

        ISecAssn updated = dao.getSa(new SpiScid(100, (short) 46), type);
        assertEquals(1, updated.getTfvn().intValue());
        assertEquals(ServiceType.PLAINTEXT, updated.getServiceType());
        assertEquals(0, (short) updated.getEst());
        assertEquals(0, (short) updated.getAst());
        assertEquals(type, updated.getType());

        node.put("saState", 2);
        body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);
        assertEquals(2, body.get("saState").asInt());

        node.put("saState", 3);
        body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);
        assertEquals(3, body.get("saState").asInt());

        node.put("saState", 1);
        body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);
        assertEquals(1, body.get("saState").asInt());

        body = restTemplate.postForObject(getUrl() + "/start", node, ObjectNode.class);
        assertEquals(3, body.get("saState").asInt());

        body = restTemplate.postForObject(getUrl() + "/stop", node, ObjectNode.class);
        assertEquals(2, body.get("saState").asInt());

        body = restTemplate.postForObject(getUrl() + "/expire", node, ObjectNode.class);
        assertEquals(1, body.get("saState").asInt());
    }

    @Test
    public void testUpdateSa() throws KmcException {
        testCreateSa();
        ObjectNode node = createSaJson();
        node.put("tfvn", 1).put("est", 0).put("ast", 0).put("serviceType", "PLAINTEXT");

        ObjectNode body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);

        assertEquals(1, body.get("tfvn").asInt());
        assertEquals("PLAINTEXT", body.get("serviceType").asText());
        assertEquals(0, body.get("est").asInt());
        assertEquals(0, body.get("ast").asInt());

        ISecAssn updated = dao.getSa(new SpiScid(100, (short) 46), FrameType.TC);
        assertEquals(1, updated.getTfvn().intValue());
        assertEquals(ServiceType.PLAINTEXT, updated.getServiceType());
        assertEquals(0, (short) updated.getEst());
        assertEquals(0, (short) updated.getAst());

        node.put("saState", 2);
        body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);
        assertEquals(2, body.get("saState").asInt());

        node.put("saState", 3);
        body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);
        assertEquals(3, body.get("saState").asInt());

        node.put("saState", 1);
        body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);
        assertEquals(1, body.get("saState").asInt());

        body = restTemplate.postForObject(getUrl() + "/start", node, ObjectNode.class);
        assertEquals(3, body.get("saState").asInt());

        body = restTemplate.postForObject(getUrl() + "/stop", node, ObjectNode.class);
        assertEquals(2, body.get("saState").asInt());

        body = restTemplate.postForObject(getUrl() + "/expire", node, ObjectNode.class);
        assertEquals(1, body.get("saState").asInt());
    }

    @Test
    public void testUpdateSaUnkeyedEncryptedByType() throws KmcException {
        updateSaUnkeyedEncryptedByType(FrameType.TC);
        updateSaUnkeyedEncryptedByType(FrameType.TM);
        updateSaUnkeyedEncryptedByType(FrameType.AOS);
    }

    public void updateSaUnkeyedEncryptedByType(FrameType type) throws KmcException {
        createSaByType(type);
        ObjectNode node = createSaJson();
        node.put("type", type.name());
        node.put("tfvn", 1).put("est", 0).put("ast", 0).put("serviceType", "ENCRYPTION");

        ObjectNode body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);

        assertEquals(1, body.get("tfvn").asInt());
        assertEquals("ENCRYPTION", body.get("serviceType").asText());
        assertEquals(1, body.get("est").asInt());
        assertEquals(0, body.get("ast").asInt());
        assertEquals(type.name(), body.get("type").asText());

        ISecAssn updated = dao.getSa(new SpiScid(100, (short) 46), type);
        assertEquals(type, updated.getType());
        assertEquals(1, updated.getTfvn().intValue());
        assertEquals(ServiceType.ENCRYPTION, updated.getServiceType());
        assertEquals(1, (short) updated.getEst());
        assertEquals(0, (short) updated.getAst());

        node.put("saState", 2);
        body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);
        assertEquals(2, body.get("saState").asInt());

        node.put("saState", 3);
        body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);
        assertEquals(3, body.get("saState").asInt());

        node.put("saState", 1);
        body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);
        assertEquals(1, body.get("saState").asInt());

        body = restTemplate.postForObject(getUrl() + "/start", node, ObjectNode.class);
        assertEquals(3, body.get("saState").asInt());

        body = restTemplate.postForObject(getUrl() + "/stop", node, ObjectNode.class);
        assertEquals(2, body.get("saState").asInt());

        body = restTemplate.postForObject(getUrl() + "/expire", node, ObjectNode.class);
        assertEquals(1, body.get("saState").asInt());

        node.put("iv", "00000000000000000000000000000001");
        node.put("ivLen", "16");
        node.put("ekid", "null");
        body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);
        assertNotNull(body);
    }

    @Test
    public void testUpdateSaUnkeyedEncrypted() throws KmcException {
        testCreateSa();
        ObjectNode node = createSaJson();
        node.put("tfvn", 1).put("est", 0).put("ast", 0).put("serviceType", "ENCRYPTION");

        ObjectNode body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);

        assertEquals(1, body.get("tfvn").asInt());
        assertEquals("ENCRYPTION", body.get("serviceType").asText());
        assertEquals(1, body.get("est").asInt());
        assertEquals(0, body.get("ast").asInt());

        ISecAssn updated = dao.getSa(new SpiScid(100, (short) 46), FrameType.TC);
        assertEquals(1, updated.getTfvn().intValue());
        assertEquals(ServiceType.ENCRYPTION, updated.getServiceType());
        assertEquals(1, (short) updated.getEst());
        assertEquals(0, (short) updated.getAst());

        node.put("saState", 2);
        body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);
        assertEquals(2, body.get("saState").asInt());

        node.put("saState", 3);
        body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);
        assertEquals(3, body.get("saState").asInt());

        node.put("saState", 1);
        body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);
        assertEquals(1, body.get("saState").asInt());

        body = restTemplate.postForObject(getUrl() + "/start", node, ObjectNode.class);
        assertEquals(3, body.get("saState").asInt());

        body = restTemplate.postForObject(getUrl() + "/stop", node, ObjectNode.class);
        assertEquals(2, body.get("saState").asInt());

        body = restTemplate.postForObject(getUrl() + "/expire", node, ObjectNode.class);
        assertEquals(1, body.get("saState").asInt());

        node.put("iv", "00000000000000000000000000000001");
        node.put("ivLen", "16");
        node.put("ekid", "null");
        body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);
        assertNotNull(body);
    }

    @Test
    public void testUpdateSaUnkeyedAuthByType() throws KmcException {
        updateSaUnkeyedAuthByType(FrameType.TC);
        updateSaUnkeyedAuthByType(FrameType.TM);
        updateSaUnkeyedAuthByType(FrameType.AOS);
    }

    public void updateSaUnkeyedAuthByType(FrameType type) throws KmcException {
        createSaByType(type);
        ObjectNode node = createSaJson();
        node.put("tfvn", 1).put("est", 0).put("ast", 0).put("serviceType", "AUTHENTICATION").put("acs", "01");
        node.putNull("ekid");
        node.put("akid", "kmc/test/key129");
        node.put("type", type.name());

        ObjectNode body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);

        assertEquals(1, body.get("tfvn").asInt());
        assertEquals("AUTHENTICATION", body.get("serviceType").asText());
        assertEquals(0, body.get("est").asInt());
        assertEquals(1, body.get("ast").asInt());
        assertEquals(type.name(), body.get("type").asText());

        ISecAssn updated = dao.getSa(new SpiScid(100, (short) 46), type);
        assertEquals(1, updated.getTfvn().intValue());
        assertEquals(ServiceType.AUTHENTICATION, updated.getServiceType());
        assertEquals(0, (short) updated.getEst());
        assertEquals(1, (short) updated.getAst());
        assertEquals(type, updated.getType());

        node.put("saState", 2);
        body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);
        assertEquals(2, body.get("saState").asInt());

        node.put("saState", 3);
        body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);
        assertEquals(3, body.get("saState").asInt());

        node.put("saState", 1);
        body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);
        assertEquals(1, body.get("saState").asInt());

        body = restTemplate.postForObject(getUrl() + "/start", node, ObjectNode.class);
        assertEquals(3, body.get("saState").asInt());

        body = restTemplate.postForObject(getUrl() + "/stop", node, ObjectNode.class);
        assertEquals(2, body.get("saState").asInt());

        body = restTemplate.postForObject(getUrl() + "/expire", node, ObjectNode.class);
        assertEquals(1, body.get("saState").asInt());

        node.put("iv", "00000000000000000000000000000001");
        node.put("ivLen", "16");
        node.put("ekid", "null");
        body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);
        assertNotNull(body);
    }

    @Test
    public void testUpdateSaUnkeyedAuth() throws KmcException {
        testCreateSa();
        ObjectNode node = createSaJson();
        node.put("tfvn", 1).put("est", 0).put("ast", 0).put("serviceType", "AUTHENTICATION").put("acs", "01");
        node.putNull("ekid");
        node.put("akid", "kmc/test/key129");

        ObjectNode body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);

        assertEquals(1, body.get("tfvn").asInt());
        assertEquals("AUTHENTICATION", body.get("serviceType").asText());
        assertEquals(0, body.get("est").asInt());
        assertEquals(1, body.get("ast").asInt());

        ISecAssn updated = dao.getSa(new SpiScid(100, (short) 46), FrameType.TC);
        assertEquals(1, updated.getTfvn().intValue());
        assertEquals(ServiceType.AUTHENTICATION, updated.getServiceType());
        assertEquals(0, (short) updated.getEst());
        assertEquals(1, (short) updated.getAst());

        node.put("saState", 2);
        body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);
        assertEquals(2, body.get("saState").asInt());

        node.put("saState", 3);
        body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);
        assertEquals(3, body.get("saState").asInt());

        node.put("saState", 1);
        body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);
        assertEquals(1, body.get("saState").asInt());

        body = restTemplate.postForObject(getUrl() + "/start", node, ObjectNode.class);
        assertEquals(3, body.get("saState").asInt());

        body = restTemplate.postForObject(getUrl() + "/stop", node, ObjectNode.class);
        assertEquals(2, body.get("saState").asInt());

        body = restTemplate.postForObject(getUrl() + "/expire", node, ObjectNode.class);
        assertEquals(1, body.get("saState").asInt());

        node.put("iv", "00000000000000000000000000000001");
        node.put("ivLen", "16");
        node.put("ekid", "null");
        body = restTemplate.postForObject(getUrl(), node, ObjectNode.class);
        assertNotNull(body);
    }

    @Test
    public void testResetArsnByType() throws KmcException {
        resetArsnByType(FrameType.TC);
        resetArsnByType(FrameType.TM);
        resetArsnByType(FrameType.AOS);
    }

    public void resetArsnByType(FrameType type) throws KmcException {
        createSaByType(type);
        ObjectNode idArsn = mapper.createObjectNode();
        idArsn.withObject("/id").put("spi", 100).put("scid", 46);
        idArsn.put("arsnLen", 8).put("arsn", "0000000000000001").put("arsnw", 10);
        idArsn.put("type", type.name());
        ObjectNode body = restTemplate.postForObject(getUrl() + "/arsn/" + type.name(), idArsn, ObjectNode.class);
        assertEquals("success", body.get("status").asText());
        ISecAssn arsn = dao.getSa(new SpiScid(100, (short) 46), type);
        assertEquals(8, (short) arsn.getArsnLen());
        assertArrayEquals(new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, arsn.getArsn());
        assertEquals(10, (short) arsn.getArsnw());
        assertEquals(type, arsn.getType());

        idArsn.put("arsn", "02");
        body = restTemplate.postForObject(getUrl() + "/arsn/" + type.name(), idArsn, ObjectNode.class);
        assertEquals("success", body.get("status").asText());
        arsn = dao.getSa(new SpiScid(100, (short) 46), type);
        assertArrayEquals(new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}, arsn.getArsn());

        idArsn.put("arsn", "000000000000000001");
        body = restTemplate.postForObject(getUrl() + "/arsn/" + type.name(), idArsn, ObjectNode.class);
        assertEquals("error", body.get("status").asText());
        arsn = dao.getSa(new SpiScid(100, (short) 46), type);
        assertArrayEquals(new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}, arsn.getArsn());
    }

    @Test
    public void testResetArsn() throws KmcException {
        testCreateSa();

        ObjectNode idArsn = mapper.createObjectNode();
        idArsn.withObject("/id").put("spi", 100).put("scid", 46);
        idArsn.put("arsnLen", 8).put("arsn", "0000000000000001").put("arsnw", 10);
        ObjectNode body = restTemplate.postForObject(getUrl() + "/arsn", idArsn, ObjectNode.class);
        assertEquals("success", body.get("status").asText());
        ISecAssn arsn = dao.getSa(new SpiScid(100, (short) 46), FrameType.TC);
        assertEquals(8, (short) arsn.getArsnLen());
        assertArrayEquals(new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, arsn.getArsn());
        assertEquals(10, (short) arsn.getArsnw());

        idArsn.put("arsn", "01");
        body = restTemplate.postForObject(getUrl() + "/arsn", idArsn, ObjectNode.class);
        assertEquals("success", body.get("status").asText());

        idArsn.put("arsn", "000000000000000001");
        body = restTemplate.postForObject(getUrl() + "/arsn", idArsn, ObjectNode.class);
        assertEquals("error", body.get("status").asText());
    }

    @Test
    public void testResetIvByType() throws KmcException {
        resetIvByType(FrameType.TC);
        resetIvByType(FrameType.TM);
        resetIvByType(FrameType.AOS);
    }

    public void resetIvByType(FrameType type) throws KmcException {
        createSaByType(type);
        ObjectNode idIv = mapper.createObjectNode();
        idIv.withObject("/id").put("spi", 100).put("scid", 46);
        idIv.put("iv", "00000000000000000000000000000001");
        idIv.put("ivLen", 16);
        ObjectNode body = restTemplate.postForObject(getUrl() + "/iv/" + type.name(), idIv, ObjectNode.class);
        assertEquals("success", body.get("status").asText());
        ISecAssn iv = dao.getSa(new SpiScid(100, (short) 46), type);
        assertEquals(type, iv.getType());
        assertEquals(16, (short) iv.getIvLen());
        assertArrayEquals(new byte[]{0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x01}, iv.getIv());

        idIv.put("iv", "02");
        body = restTemplate.postForObject(getUrl() + "/iv/" + type.name(), idIv, ObjectNode.class);
        assertEquals("success", body.get("status").asText());
        iv = dao.getSa(new SpiScid(100, (short) 46), type);
        assertEquals(type, iv.getType());
        assertArrayEquals(new byte[]{0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x02}, iv.getIv());

        idIv.put("ivLen", 2);
        idIv.put("iv", "00000001");
        body = restTemplate.postForObject(getUrl() + "/iv/" + type.name(), idIv, ObjectNode.class);
        assertEquals("error", body.get("status").asText());
    }

    @Test
    public void testResetIv() throws KmcException {
        testCreateSa();
        ObjectNode idIv = mapper.createObjectNode();
        idIv.withObject("/id").put("spi", 100).put("scid", 46);
        idIv.put("iv", "00000000000000000000000000000001");
        idIv.put("ivLen", 16);
        ObjectNode body = restTemplate.postForObject(getUrl() + "/iv", idIv, ObjectNode.class);
        assertEquals("success", body.get("status").asText());
        ISecAssn iv = dao.getSa(new SpiScid(100, (short) 46), FrameType.TC);
        assertEquals(16, (short) iv.getIvLen());
        assertArrayEquals(new byte[]{0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x01}, iv.getIv());

        idIv.put("iv", "02");
        body = restTemplate.postForObject(getUrl() + "/iv", idIv, ObjectNode.class);
        assertEquals("success", body.get("status").asText());
        iv = dao.getSa(new SpiScid(100, (short) 46), FrameType.TC);
        assertArrayEquals(new byte[]{0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x02}, iv.getIv());

        idIv.put("ivLen", 2);
        idIv.put("iv", "00000001");
        body = restTemplate.postForObject(getUrl() + "/iv", idIv, ObjectNode.class);
        assertEquals("error", body.get("status").asText());
    }

    @Test
    public void testRekeyByType() throws KmcException {
        rekeyByType(FrameType.TC);
        rekeyByType(FrameType.TM);
        rekeyByType(FrameType.AOS);
    }

    public void rekeyByType(FrameType type) throws KmcException {
        createSaByType(type);
        ObjectNode rekey = mapper.createObjectNode();
        rekey.withObject("/id").put("spi", 100).put("scid", 46);
        rekey.put("ekid", "bogus/ekid");
        ObjectNode body = restTemplate.postForObject(getUrl() + "/key/" + type.name(), rekey, ObjectNode.class);
        assertEquals("success", body.get("status").asText());
        ISecAssn keyed = dao.getSa(new SpiScid(100, (short) 46), type);
        assertEquals(type, keyed.getType());
        assertEquals("bogus/ekid", keyed.getEkid());
        rekey.put("akid", "bogus/akid");
        rekey.put("ekid", "");
        body = restTemplate.postForObject(getUrl() + "/key/" + type.name(), rekey, ObjectNode.class);
        assertEquals("success", body.get("status").asText());
        keyed = dao.getSa(new SpiScid(100, (short) 46), type);
        assertEquals(type, keyed.getType());
        assertEquals("bogus/akid", keyed.getAkid());
        assertEquals("", keyed.getEkid());
        rekey.put("akid", "bogus/akid/2");
        rekey.put("ekid", "bogus/ekid/2");
        body = restTemplate.postForObject(getUrl() + "/key/" + type.name(), rekey, ObjectNode.class);
        assertEquals("success", body.get("status").asText());
        keyed = dao.getSa(new SpiScid(100, (short) 46), type);
        assertEquals(type, keyed.getType());
        assertEquals("bogus/akid/2", keyed.getAkid());
        assertEquals("bogus/ekid/2", keyed.getEkid());
    }

    @Test
    public void testRekey() throws KmcException {
        testCreateSa();
        ObjectNode rekey = mapper.createObjectNode();
        rekey.withObject("/id").put("spi", 100).put("scid", 46);
        rekey.put("ekid", "bogus/ekid");
        ObjectNode body = restTemplate.postForObject(getUrl() + "/key", rekey, ObjectNode.class);
        assertEquals("success", body.get("status").asText());
        ISecAssn keyed = dao.getSa(new SpiScid(100, (short) 46), FrameType.TC);
        assertEquals("bogus/ekid", keyed.getEkid());
        rekey.put("akid", "bogus/akid");
        rekey.put("ekid", "");
        body = restTemplate.postForObject(getUrl() + "/key", rekey, ObjectNode.class);
        assertEquals("success", body.get("status").asText());
        keyed = dao.getSa(new SpiScid(100, (short) 46), FrameType.TC);
        assertEquals("bogus/akid", keyed.getAkid());
        assertEquals("", keyed.getEkid());
        rekey.put("akid", "bogus/akid/2");
        rekey.put("ekid", "bogus/ekid/2");
        body = restTemplate.postForObject(getUrl() + "/key", rekey, ObjectNode.class);
        assertEquals("success", body.get("status").asText());
        keyed = dao.getSa(new SpiScid(100, (short) 46), FrameType.TC);
        assertEquals("bogus/akid/2", keyed.getAkid());
        assertEquals("bogus/ekid/2", keyed.getEkid());
    }

    @Test
    public void testGetCsvByType() throws IOException, KmcException {
        getCsvByType(FrameType.TC);
        getCsvByType(FrameType.TM);
        getCsvByType(FrameType.AOS);
    }

    public void getCsvByType(FrameType type) throws IOException, KmcException {
        createSaByType(type);
        String csvResp = restTemplate.getForObject(getUrl() + "/csv/" + type.name(), String.class);
        assertNotNull(csvResp);
        List<String> entries = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new StringReader(csvResp))) {
            String line;
            while ((line = reader.readLine()) != null) {
                entries.add(line);
            }
        }
        assertEquals(7, entries.size());
    }

    @Test
    public void testGetCsv() throws IOException, KmcException {
        testCreateSa();
        String csvResp = restTemplate.getForObject(getUrl() + "/csv", String.class);
        assertNotNull(csvResp);
        List<String> entries = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new StringReader(csvResp))) {
            String line;
            while ((line = reader.readLine()) != null) {
                entries.add(line);
            }
        }
        assertEquals(17, entries.size());
    }

    @Test
    public void testBulkUpload() throws KmcException {
        testCreateSa();
        // test bulk creating SAs
        HttpHeaders header = new HttpHeaders();
        header.setContentType(MediaType.MULTIPART_FORM_DATA);
        MultiValueMap<String, Object> csvBody = new LinkedMultiValueMap<>();
        csvBody.add("file", new FileSystemResource(getClass().getClassLoader().getResource("test.csv").getPath()));
        HttpEntity<MultiValueMap<String, Object>> csvUploadReq = new HttpEntity<>(csvBody, header);

        // this should fail with an error response, the SAs already exist
        ObjectNode body = restTemplate.postForObject(getUrl() + "/create", csvUploadReq, ObjectNode.class);
        assertEquals("error", body.get("status").asText());
        assertEquals(6, body.get("messages").size());

        // this forces creation for existing, which should succeed
        csvBody.add("force", "true");
        csvUploadReq = new HttpEntity<>(csvBody, header);
        body = restTemplate.postForObject(getUrl() + "/create", csvUploadReq, ObjectNode.class);
        assertEquals("success", body.get("status").asText());
    }

    @Test
    public void testDeleteSaByType() throws KmcException {
        deleteSaByType(FrameType.TC);
        deleteSaByType(FrameType.TM);
        deleteSaByType(FrameType.AOS);
    }

    public void deleteSaByType(FrameType type) throws KmcException {
        createSaByType(type);
        ISecAssn present = dao.getSa(new SpiScid(100, (short) 46), type);
        assertNotNull(present);
        assertEquals(type, present.getType());

        ArrayNode  anode = mapper.createArrayNode();
        ObjectNode node  = anode.addObject();
        node.put("spi", 100);
        node.put("scid", 46);
        HttpEntity<JsonNode> entity = new HttpEntity<>(anode);
        restTemplate.exchange(getUrl() + "/" + type.name(), HttpMethod.DELETE, entity, JsonNode.class);
        ISecAssn deleted = dao.getSa(new SpiScid(100, (short) 46), type);
        assertNull(deleted);
    }

    @Test
    public void testDeleteSa() throws KmcException {
        testCreateSa();
        ArrayNode  anode = mapper.createArrayNode();
        ObjectNode node  = anode.addObject();
        node.put("spi", 100);
        node.put("scid", 46);
        HttpEntity<JsonNode> entity = new HttpEntity<>(anode);
        restTemplate.exchange(getUrl(), HttpMethod.DELETE, entity, JsonNode.class);
        ISecAssn deleted = dao.getSa(new SpiScid(100, (short) 46), FrameType.TC);
        assertNull(deleted);
    }

}