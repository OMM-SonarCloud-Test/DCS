package gov.nasa.jpl.ammos.asec.kmc.cli.crud;

import gov.nasa.jpl.ammos.asec.kmc.api.ex.KmcException;
import gov.nasa.jpl.ammos.asec.kmc.api.sa.FrameType;
import gov.nasa.jpl.ammos.asec.kmc.api.sa.ISecAssn;
import gov.nasa.jpl.ammos.asec.kmc.api.sa.SpiScid;
import org.junit.Test;
import picocli.CommandLine;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

/**
 * Tests for keying an SA
 */
public class SaKeyTest extends BaseCommandLineTest {

    @Test
    public void testRekey() throws KmcException {
        testRekey(FrameType.TC);
        testRekey(FrameType.TM);
        testRekey(FrameType.AOS);
    }

    public void testRekey(FrameType type) throws KmcException {
        CommandLine cli = getCmd(new SaKey(), true);
        int exit = cli.execute("--spi=1", "--scid=46", "--akid=130", "--acs=0x01", "-y", String.format("--type=%s",
                type.name()));
        assertEquals(0, exit);
        ISecAssn sa = dao.getSa(new SpiScid(1, (short) 46), type);
        assertEquals("130", sa.getAkid());
        assertEquals(1, (short) sa.getAcsLen());
        assertArrayEquals(new byte[]{0x01}, sa.getAcs());

        exit = cli.execute("--spi=1", "--scid=46", "--ekid=140", "--ecs=02", "-y", String.format("--type=%s",
                type.name()));
        assertEquals(0, exit);
        sa = dao.getSa(new SpiScid(1, (short) 46), type);
        assertEquals("140", sa.getEkid());
        assertEquals(1, (short) sa.getEcsLen());
        assertArrayEquals(new byte[]{0x02}, sa.getEcs());

        exit = cli.execute("--spi=2", "--scid=46", "--ekid=140", "--ecs=0002", "--akid=140", "--acs" + "=0002", "-y",
                String.format("--type=%s", type.name()));
        assertEquals(0, exit);
        sa = dao.getSa(new SpiScid(2, (short) 46), type);
        assertEquals("140", sa.getEkid());
        assertEquals(1, (short) sa.getEcsLen());
        assertArrayEquals(new byte[]{0x00, 0x02}, sa.getEcs());
        assertEquals("140", sa.getAkid());
        assertEquals(1, (short) sa.getAcsLen());
        assertArrayEquals(new byte[]{0x00, 0x02}, sa.getAcs());
    }

    @Test
    public void testRekeyConfirm() throws KmcException {
        testRekeyConfirm(FrameType.TC);
        testRekeyConfirm(FrameType.AOS);
        testRekeyConfirm(FrameType.TM);
    }

    public void testRekeyConfirm(FrameType type) throws KmcException {
        InputStream old = System.in;
        InputStream is  = new ByteArrayInputStream("y".getBytes(StandardCharsets.UTF_8));
        System.setIn(is);
        CommandLine cli = getCmd(new SaKey(), true);
        int exit = cli.execute("--spi=1", "--scid=46", "--akid=130", "--acs=0x01", String.format("--type=%s",
                type.name()));
        assertEquals(0, exit);
        ISecAssn sa = dao.getSa(new SpiScid(1, (short) 46), type);
        assertEquals("130", sa.getAkid());
        assertEquals(1, (short) sa.getAcsLen());
        assertArrayEquals(new byte[]{0x01}, sa.getAcs());
        System.setIn(old);
    }

    @Test
    public void testRekeyReject() throws KmcException {
        testRekeyReject(FrameType.TM);
        testRekeyReject(FrameType.AOS);
        testRekeyReject(FrameType.TC);
    }

    public void testRekeyReject(FrameType type) throws KmcException {
        InputStream old = System.in;
        InputStream is  = new ByteArrayInputStream("n".getBytes(StandardCharsets.UTF_8));
        System.setIn(is);
        CommandLine cli = getCmd(new SaKey(), true);
        int exit = cli.execute("--spi=1", "--scid=46", "--akid=130", "--acs=0x01", String.format("--type=%s",
                type.name()));
        assertEquals(0, exit);
        ISecAssn sa = dao.getSa(new SpiScid(1, (short) 46), type);
        assertNull(sa.getAkid());
        assertEquals(0, (short) sa.getAcsLen());
        assertArrayEquals(new byte[]{0x00}, sa.getAcs());
        System.setIn(old);
    }

    @Test
    public void testRekeyFail() {
        testRekeyFail(FrameType.TC);
        testRekeyFail(FrameType.AOS);
        testRekeyFail(FrameType.TM);
    }

    public void testRekeyFail(FrameType type) {
        CommandLine cli  = getCmd(new SaKey(), true);
        int         exit = cli.execute("--spi=1", "--scid=46", String.format("--type=%s", type.name()));
        assertNotEquals(0, exit);

        exit = cli.execute("--spi=1", "--scid=46", "--ekid=130", String.format("--type=%s", type.name()));
        assertNotEquals(0, exit);

        exit = cli.execute("--spi=1", "--scid=46", "--ecslen=1", String.format("--type=%s", type.name()));
        assertNotEquals(0, exit);

        exit = cli.execute("--spi=1", "--scid=46", "--ecs=01", String.format("--type=%s", type.name()));
        assertNotEquals(0, exit);

        exit = cli.execute("--spi=1", "--scid=46", "--ekid=130", String.format("--type=%s", type.name()));
        assertNotEquals(0, exit);

        exit = cli.execute("--spi=1", "--scid=46", "--ecs=01", "-y", String.format("--type=%s", type.name()));
        assertNotEquals(0, exit);

        exit = cli.execute("--spi=1", "--scid=46", "--ekid=130", "--ecs=01", "--akid=140", String.format("--type=%s",
                type.name()));
        assertNotEquals(0, exit);

        exit = cli.execute("--spi=1", "--scid=46", "--akid=130", String.format("--type=%s", type.name()));
        assertNotEquals(0, exit);

        exit = cli.execute("--spi=1", "--scid=46", "--acs=01", String.format("--type=%s", type.name()));
        assertNotEquals(0, exit);

        exit = cli.execute("--spi=1", "--scid=46", String.format("--type=%s", type.name()));
        assertNotEquals(0, exit);

        exit = cli.execute("--spi=1", "--scid=46", "--akid=130", String.format("--type=%s", type.name()));
        assertNotEquals(0, exit);

        exit = cli.execute("--spi=1", "--scid=46", "--acs=01", String.format("--type=%s", type.name()));
        assertNotEquals(0, exit);

        exit = cli.execute("--spi=1", "--scid=46", "--akid=140", "--acs=01", "--ekid=140", String.format("--type=%s",
                type.name()));
        assertNotEquals(0, exit);
    }

}