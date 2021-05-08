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
package org.cyclonedx.util;

import java.io.IOException;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.fasterxml.jackson.dataformat.xml.ser.ToXmlGenerator;
import org.cyclonedx.model.ExtensibleType;
import org.cyclonedx.model.Extension;
import org.cyclonedx.model.Extension.ExtensionType;
import org.cyclonedx.model.vulnerability.Rating;
import org.cyclonedx.model.vulnerability.Vulnerability10;
import org.cyclonedx.model.vulnerability.Vulnerability10.Advisory;
import org.cyclonedx.model.vulnerability.Vulnerability10.Cwe;
import org.cyclonedx.model.vulnerability.Vulnerability10.Recommendation;

public class ExtensionSerializer
    extends StdSerializer<Extension>
{
  private ObjectMapper mapper;

  public ExtensionSerializer() {
    this(null);
  }

  public ExtensionSerializer(final Class<Extension> t) {
    super(t);
    this.mapper = new ObjectMapper();
  }

  @Override
  public void serialize(
      final Extension value, final JsonGenerator gen, final SerializerProvider provider) throws IOException
  {
    if (value.getExtensionType().equals(ExtensionType.VULNERABILITIES)) {
      if (gen instanceof ToXmlGenerator) {
        try {
          serializeVulnerabilities((ToXmlGenerator) gen, value);
        }
        catch (XMLStreamException e) {
          throw new IOException(e);
        }
      } else {
        serializeVulnerabilitiesToJson(gen, value);
      }
    }
  }

  private void serializeVulnerabilitiesToJson(final JsonGenerator gen, final Extension vulns) throws IOException {
    mapper.writeValue(gen, vulns.getExtensions());
  }

  private void serializeVulnerabilities(final ToXmlGenerator gen, final Extension vulns)
      throws XMLStreamException
  {
    final XMLStreamWriter staxWriter = gen.getStaxWriter();
    staxWriter.writeStartElement(Vulnerability10.PREFIX, Vulnerability10.VULNERABILITIES, Vulnerability10.NAMESPACE_URI);

    for (ExtensibleType ext : vulns.getExtensions()) {
      final Vulnerability10 vuln = (Vulnerability10) ext;
      staxWriter.writeStartElement(Vulnerability10.PREFIX, Vulnerability10.NAME, Vulnerability10.NAMESPACE_URI);
      staxWriter.writeAttribute(Vulnerability10.REF, vuln.getRef());

      generateTextNode(staxWriter, Vulnerability10.ID, vuln.getId(), Vulnerability10.NAMESPACE_URI, Vulnerability10.PREFIX);
      processRatings(staxWriter, vuln);
      processCwes(staxWriter, vuln);
      generateTextNode(staxWriter, Vulnerability10.DESCRIPTION, vuln.getDescription(), Vulnerability10.NAMESPACE_URI, Vulnerability10.PREFIX);
      processRecommendations(staxWriter, vuln);
      processAdvisories(staxWriter, vuln);
      processSource(staxWriter, vuln);

      staxWriter.writeEndElement();
    }

    staxWriter.writeEndElement();
  }

  private void processAdvisories(final XMLStreamWriter staxWriter, final Vulnerability10 vuln)
      throws XMLStreamException
  {
    if (vuln.getAdvisories() != null && !vuln.getAdvisories().isEmpty()) {
      staxWriter.writeStartElement(Vulnerability10.PREFIX, Vulnerability10.ADVISORIES, Vulnerability10.NAMESPACE_URI);
      for (Advisory a : vuln.getAdvisories()) {
        generateTextNode(staxWriter, Vulnerability10.ADVISORY, a.getText(), Vulnerability10.NAMESPACE_URI, Vulnerability10.PREFIX);
      }
      staxWriter.writeEndElement();
    }
  }

  private void processRecommendations(final XMLStreamWriter staxWriter, final Vulnerability10 vuln)
      throws XMLStreamException
  {
    if (vuln.getRecommendations() != null && !vuln.getRecommendations().isEmpty()) {
      staxWriter.writeStartElement(Vulnerability10.PREFIX, Vulnerability10.RECOMMENDATIONS, Vulnerability10.NAMESPACE_URI);
      for (Recommendation r : vuln.getRecommendations()) {
        generateTextNode(staxWriter, Vulnerability10.RECOMMENDATION, r.getText(), Vulnerability10.NAMESPACE_URI, Vulnerability10.PREFIX);
      }
      staxWriter.writeEndElement();
    }
  }

  private void processCwes(final XMLStreamWriter staxWriter, final Vulnerability10 vuln)
      throws XMLStreamException
  {
    if (vuln.getCwes() != null && !vuln.getCwes().isEmpty()) {
      staxWriter.writeStartElement(Vulnerability10.PREFIX, Vulnerability10.CWES, Vulnerability10.NAMESPACE_URI);
      for (Cwe c : vuln.getCwes()) {
        generateTextNodeFromNumber(staxWriter, Vulnerability10.CWE, c.getText(), Vulnerability10.NAMESPACE_URI, Vulnerability10.PREFIX);
      }
      staxWriter.writeEndElement();
    }
  }

  private void processSource(final XMLStreamWriter staxWriter, final Vulnerability10 vulnerability)
      throws XMLStreamException
  {
    if (vulnerability.getSource() != null && vulnerability.getSource().getName() != null) {
      staxWriter.writeStartElement(Vulnerability10.PREFIX, Vulnerability10.SOURCE, Vulnerability10.NAMESPACE_URI);
      staxWriter.writeAttribute(Vulnerability10.SOURCE_NAME, vulnerability.getSource().getName());
      if (vulnerability.getSource().getUrl() != null) {
        generateTextNode(staxWriter, Vulnerability10.URL, vulnerability.getSource().getUrl().toString(),
            Vulnerability10.NAMESPACE_URI, Vulnerability10.PREFIX);
      }
      staxWriter.writeEndElement();
    }
  }

  private void processRatings(final XMLStreamWriter staxWriter, final Vulnerability10 vuln)
      throws XMLStreamException
  {
    if (vuln.getRatings() != null && !vuln.getRatings().isEmpty()) {
      staxWriter.writeStartElement(Vulnerability10.PREFIX, Vulnerability10.RATINGS, Vulnerability10.NAMESPACE_URI);
      for (Rating r : vuln.getRatings()) {
        staxWriter.writeStartElement(Vulnerability10.PREFIX, Vulnerability10.RATING, Vulnerability10.NAMESPACE_URI);
        if (r.getScore() != null) {
          staxWriter.writeStartElement(Vulnerability10.PREFIX, Vulnerability10.SCORE, Vulnerability10.NAMESPACE_URI);
          generateTextNodeFromNumber(staxWriter, Vulnerability10.BASE, r.getScore().getBase(), Vulnerability10.NAMESPACE_URI, Vulnerability10.PREFIX);
          generateTextNodeFromNumber(staxWriter, Vulnerability10.IMPACT, r.getScore().getImpact(), Vulnerability10.NAMESPACE_URI, Vulnerability10.PREFIX);
          generateTextNodeFromNumber(staxWriter, Vulnerability10.EXPLOITABILITY, r.getScore().getExploitability(), Vulnerability10.NAMESPACE_URI, Vulnerability10.PREFIX);
          staxWriter.writeEndElement();
        }
        if (r.getSeverity() != null) {
          generateTextNode(staxWriter, Vulnerability10.SEVERITY, r.getSeverity().getSeverityName(),
              Vulnerability10.NAMESPACE_URI, Vulnerability10.PREFIX);
        }
        if (r.getMethod() != null) {
          generateTextNode(staxWriter, Vulnerability10.METHOD, r.getMethod().getScoreSourceName(),
              Vulnerability10.NAMESPACE_URI, Vulnerability10.PREFIX);
        }
        generateTextNode(staxWriter, Vulnerability10.VECTOR, r.getVector(), Vulnerability10.NAMESPACE_URI, Vulnerability10.PREFIX);
        staxWriter.writeEndElement();
      }
      staxWriter.writeEndElement();
    }
  }

  private void generateTextNodeFromNumber(final XMLStreamWriter writer,
                                          final String fieldName,
                                          final Number value,
                                          final String namespaceUri,
                                          final String prefix) throws XMLStreamException
  {
    if ( value != null) {
      generateTextNode(writer, fieldName, value.toString(), namespaceUri, prefix);
    }
  }

  private void generateTextNode(final XMLStreamWriter writer,
                                final String fieldName,
                                final String value,
                                final String namespaceUri,
                                final String prefix) throws XMLStreamException
  {
    if ( value != null) {
      writer.writeStartElement(prefix, fieldName, namespaceUri);
      writer.writeCharacters(value);
      writer.writeEndElement();
    }
  }
}
