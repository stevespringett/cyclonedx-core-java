/*
 * This file is part of CycloneDX Core (Java).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.cyclonedx.parsers;

import org.apache.commons.io.IOUtils;
import org.cyclonedx.CycloneDxSchema;
import org.cyclonedx.model.*;
import org.junit.Assert;
import org.junit.Test;
import java.io.File;
import java.util.List;

public class JsonParserTest {

    @Test
    public void testValid12Bom() throws Exception {
        final File file = new File(this.getClass().getResource("/bom-1.2.json").getFile());
        final JsonParser parser = new JsonParser();
        Bom bom = parser.parse(file);
        Assert.assertTrue(parser.isValid(file, CycloneDxSchema.Version.VERSION_12, true));
        System.out.println(bom.getSerialNumber());
    }

    @Test
    public void testParsedObjects12Bom() throws Exception {
        final byte[] bomBytes = IOUtils.toByteArray(this.getClass().getResourceAsStream("/bom-1.2.json"));
        final JsonParser parser = new JsonParser();
        final Bom bom = parser.parse(bomBytes);
        Assert.assertEquals("1.2", bom.getSpecVersion());
        Assert.assertEquals(3, bom.getComponents().size());
        Assert.assertEquals(1, bom.getVersion());
        Assert.assertNotNull(bom.getMetadata());
        Assert.assertNotNull(bom.getMetadata().getTimestamp());
        Assert.assertEquals(1, bom.getMetadata().getTools().size());
        Assert.assertEquals("Awesome Vendor", bom.getMetadata().getTools().get(0).getVendor());
        Assert.assertEquals("Awesome Tool", bom.getMetadata().getTools().get(0).getName());
        Assert.assertEquals("9.1.2", bom.getMetadata().getTools().get(0).getVersion());
        Assert.assertEquals(2, bom.getMetadata().getTools().get(0).getHashes().size());
        Assert.assertEquals("SHA-1", bom.getMetadata().getTools().get(0).getHashes().get(0).getAlgorithm());
        Assert.assertEquals("25ed8e31b995bb927966616df2a42b979a2717f0", bom.getMetadata().getTools().get(0).getHashes().get(0).getValue());
        Assert.assertEquals(1, bom.getMetadata().getAuthors().size());
        Assert.assertEquals("Samantha Wright", bom.getMetadata().getAuthors().get(0).getName());
        Assert.assertEquals("samantha.wright@example.com", bom.getMetadata().getAuthors().get(0).getEmail());
        Assert.assertEquals("800-555-1212", bom.getMetadata().getAuthors().get(0).getPhone());
        Assert.assertEquals("Acme Application", bom.getMetadata().getComponent().getName());
        Assert.assertEquals("9.1.1", bom.getMetadata().getComponent().getVersion());
        Assert.assertEquals(Component.Type.APPLICATION, bom.getMetadata().getComponent().getType());
        Assert.assertNotNull(bom.getMetadata().getComponent().getSwid());
        Assert.assertEquals("swidgen-242eb18a-503e-ca37-393b-cf156ef09691_9.1.1", bom.getMetadata().getComponent().getSwid().getTagId());
        Assert.assertEquals("Acme Application", bom.getMetadata().getComponent().getSwid().getName());
        Assert.assertEquals("9.1.1", bom.getMetadata().getComponent().getSwid().getVersion());
        Assert.assertEquals(0, bom.getMetadata().getComponent().getSwid().getTagVersion());
        Assert.assertEquals(false, bom.getMetadata().getComponent().getSwid().isPatch());
        Assert.assertEquals("Acme, Inc.", bom.getMetadata().getManufacture().getName());
        Assert.assertEquals("https://example.com", bom.getMetadata().getManufacture().getUrls().get(0));
        Assert.assertEquals(1, bom.getMetadata().getManufacture().getContacts().size());
        Assert.assertEquals("Acme Professional Services", bom.getMetadata().getManufacture().getContacts().get(0).getName());
        Assert.assertEquals("professional.services@example.com", bom.getMetadata().getManufacture().getContacts().get(0).getEmail());
        Assert.assertEquals("Acme, Inc.", bom.getMetadata().getSupplier().getName());
        Assert.assertEquals("https://example.com", bom.getMetadata().getSupplier().getUrls().get(0));
        Assert.assertEquals(1, bom.getMetadata().getSupplier().getContacts().size());
        Assert.assertEquals("Acme Distribution", bom.getMetadata().getSupplier().getContacts().get(0).getName());
        Assert.assertEquals("distribution@example.com", bom.getMetadata().getSupplier().getContacts().get(0).getEmail());

        final List<Component> components = bom.getComponents();
        Assert.assertEquals(3, components.size());
        Component c1 = components.get(0);
        Assert.assertEquals("com.acme", c1.getGroup());
        Assert.assertEquals("tomcat-catalina", c1.getName());
        Assert.assertEquals("9.0.14", c1.getVersion());
        Assert.assertEquals(Component.Type.LIBRARY, c1.getType());
        Assert.assertEquals("pkg:npm/acme/component@1.0.0", c1.getPurl());

        Component c3 = components.get(2);
        Assert.assertEquals(Component.Type.LIBRARY, c3.getType());
        Assert.assertEquals("pkg:maven/org.glassfish.hk2/osgi-resource-locator@1.0.1?type=jar", c3.getBomRef());
        Assert.assertEquals("GlassFish Community", c3.getPublisher());
        Assert.assertEquals("org.glassfish.hk2", c3.getGroup());
        Assert.assertEquals("osgi-resource-locator", c3.getName());
        Assert.assertEquals("1.0.1", c3.getVersion());
        Assert.assertEquals( "(CDDL-1.0 OR GPL-2.0-with-classpath-exception)", c3.getLicenseChoice().getExpression());

        testPedigree(c1);

        // Begin Services
        List<Service> services = bom.getServices();
        Assert.assertEquals(1, services.size());
        Service s = services.get(0);
        OrganizationalEntity provider = s.getProvider();
        Assert.assertNotNull(provider);
        Assert.assertEquals("Partner Org", provider.getName());
        List<String> urls = provider.getUrls();
        Assert.assertEquals(1, urls.size());
        Assert.assertEquals("https://partner.org", urls.get(0));
        List<OrganizationalContact> contacts = provider.getContacts();
        Assert.assertEquals(1, contacts.size());
        OrganizationalContact contact = contacts.get(0);
        Assert.assertEquals("Support", contact.getName());
        Assert.assertEquals("support@partner", contact.getEmail());
        Assert.assertEquals("800-555-1212", contact.getPhone());
        Assert.assertEquals("org.partner", s.getGroup());
        Assert.assertEquals("Stock ticker service", s.getName());
        Assert.assertEquals("2020-Q2", s.getVersion());
        Assert.assertEquals("Provides real-time stock information", s.getDescription());
        List<String> endpoints = s.getEndpoints();
        Assert.assertEquals(2, endpoints.size());
        Assert.assertEquals("https://partner.org/api/v1/lookup", endpoints.get(0));
        Assert.assertEquals("https://partner.org/api/v1/stock", endpoints.get(1));
        Assert.assertNotNull(s.getAuthenticated());
        Assert.assertNotNull(s.getxTrustBoundary());
        Assert.assertTrue(s.getAuthenticated());
        Assert.assertTrue(s.getxTrustBoundary());
        List<ServiceData> data = s.getData();
        Assert.assertEquals(3, data.size());
        Assert.assertEquals("inbound", data.get(0).getFlow().getFlowName());
        Assert.assertEquals("PII", data.get(0).getClassification());
        Assert.assertEquals(ServiceData.Flow.OUTBOUND, data.get(1).getFlow());
        Assert.assertEquals("PIFI", data.get(1).getClassification());
        Assert.assertEquals(ServiceData.Flow.BI_DIRECTIONAL, data.get(2).getFlow());
        Assert.assertEquals("pubic", data.get(2).getClassification());
        Assert.assertNotNull(s.getLicense());
        Assert.assertEquals(1, s.getLicense().getLicenses().size());
        Assert.assertEquals("Partner license", s.getLicense().getLicenses().get(0).getName());
        Assert.assertEquals(2, s.getExternalReferences().size());
        Assert.assertEquals(ExternalReference.Type.WEBSITE, s.getExternalReferences().get(0).getType());
        Assert.assertEquals("http://partner.org", s.getExternalReferences().get(0).getUrl());
        Assert.assertEquals(ExternalReference.Type.DOCUMENTATION, s.getExternalReferences().get(1).getType());
        Assert.assertEquals("http://api.partner.org/swagger", s.getExternalReferences().get(1).getUrl());
        // End Services

        // Begin Dependencies
        Assert.assertEquals(1, bom.getDependencies().size());
        Dependency d1 = bom.getDependencies().get(0);
        Assert.assertNotNull(d1);
        Assert.assertEquals("pkg:npm/acme/component@1.0.0", d1.getRef());
        Assert.assertEquals(1, d1.getDependencies().size());
        Dependency d11 = d1.getDependencies().get(0);
        Assert.assertEquals("pkg:npm/acme/common@1.0.0", d11.getRef());
        Assert.assertNull(d11.getDependencies());
    }

    @Test
    public void testValid12BomWithVulnerabilities() throws Exception {
        final byte[] bomBytes = IOUtils.toByteArray(this.getClass().getResourceAsStream("/bom-1.2-vulnerability.json"));
        final JsonParser parser = new JsonParser();
        final Bom bom = parser.parse(bomBytes);
        Assert.assertNotNull(bom);
    }

    private void testPedigree(final Component component) {
        Assert.assertNotNull(component.getPedigree());
        Assert.assertNotNull(component.getPedigree().getAncestors());
        Assert.assertEquals(2, component.getPedigree().getAncestors().getComponents().size());
        Assert.assertNotNull(component.getPedigree().getDescendants());
        Assert.assertEquals(2, component.getPedigree().getDescendants().getComponents().size());
        Assert.assertNotNull(component.getPedigree().getVariants());
        Assert.assertEquals(2, component.getPedigree().getVariants().getComponents().size());
    }
}
