package org.cyclonedx;

import org.apache.commons.io.IOUtils;
import org.cyclonedx.CycloneDxSchema.Version;
import org.cyclonedx.generators.json.BomJsonGenerator;
import org.cyclonedx.generators.json.BomJsonGenerator12;
import org.cyclonedx.model.Bom;
import org.cyclonedx.parsers.JsonParser;
import org.cyclonedx.parsers.XmlParser;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import javax.json.JsonObject;

public class BomJsonGeneratorTest {

    private File tempFile;

    @Before
    public void before() throws IOException {
        Path path = Files.createTempDirectory("cyclonedx-core-java");
        this.tempFile = new File(path.toFile(), "bom.json");
    }

    @After
    public void after() {
        tempFile.delete();
        tempFile.getParentFile().delete();
    }

    @Test
    public void schema12GenerationTest() throws Exception {
        Bom bom =  createCommonBom("/bom-1.2.xml");
        BomJsonGenerator generator = BomGeneratorFactory.createJson(Version.VERSION_12, bom);
        Assert.assertTrue(generator instanceof BomJsonGenerator12);
        Assert.assertEquals(CycloneDxSchema.Version.VERSION_12, generator.getSchemaVersion());
        File file = writeToFile(generator.toJsonString());
        JsonParser parser = new JsonParser();
        Assert.assertTrue(parser.isValid(file, CycloneDxSchema.Version.VERSION_12, true));
    }

    @Test
    public void schema12GenerationTestWithVulns() throws Exception {
        Bom bom = createCommonBom("/bom-1.2-vulnerability.xml");
        BomJsonGenerator generator = BomGeneratorFactory.createJson(Version.VERSION_12, bom);
        Assert.assertTrue(generator instanceof BomJsonGenerator12);
        Assert.assertEquals(CycloneDxSchema.Version.VERSION_12, generator.getSchemaVersion());
        File file = writeToFile(generator.toJsonString());
        JsonParser parser = new JsonParser();
        Assert.assertTrue(parser.isValid(file, CycloneDxSchema.Version.VERSION_12, true));
    }

    @Test
    public void schema12JsonObjectGenerationTest() throws Exception {
        Bom bom = createCommonBom("/bom-1.2.xml");
        BomJsonGenerator generator = BomGeneratorFactory.createJson(Version.VERSION_12, bom);
        JsonObject obj = generator.toJsonObject();
        Assert.assertNotNull(obj);
        Assert.assertEquals("CycloneDX", obj.getString("bomFormat"));
        Assert.assertEquals("1.2", obj.getString("specVersion"));
        Assert.assertEquals("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", obj.getString("serialNumber"));
        Assert.assertEquals(1, obj.getInt("version"));
        Assert.assertEquals(6, obj.getJsonObject("metadata").size());
        Assert.assertEquals(3, obj.getJsonArray("components").size());
    }

    private File writeToFile(String jsonString) throws Exception {
        try (FileWriter writer = new FileWriter(tempFile.getAbsolutePath())) {
            writer.write(jsonString);
        }
        return tempFile;
    }

    private Bom createCommonBom(String resource) throws Exception {
        final byte[] bomBytes = IOUtils.toByteArray(this.getClass().getResourceAsStream(resource));
        XmlParser parser = new XmlParser();
        return parser.parse(bomBytes);
    }
}
