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
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.TreeNode;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.dataformat.xml.deser.FromXmlParser;
import org.apache.commons.lang3.math.NumberUtils;
import org.cyclonedx.model.ExtensibleType;
import org.cyclonedx.model.Extension;
import org.cyclonedx.model.Extension.ExtensionType;
import org.cyclonedx.model.vulnerability.Rating;
import org.cyclonedx.model.vulnerability.Vulnerability10;
import org.cyclonedx.model.vulnerability.Vulnerability10.Advisory;
import org.cyclonedx.model.vulnerability.Vulnerability10.Cwe;
import org.cyclonedx.model.vulnerability.Vulnerability10.Recommendation;
import org.cyclonedx.model.vulnerability.Vulnerability10.Score;
import org.cyclonedx.model.vulnerability.Vulnerability10.ScoreSource;
import org.cyclonedx.model.vulnerability.Vulnerability10.Severity;
import org.cyclonedx.model.vulnerability.Vulnerability10.Source;

public class ExtensionDeserializer extends StdDeserializer<Extension>
{
  public ExtensionDeserializer() {
    this(Extension.class);
  }

  public ExtensionDeserializer(final Class vc) {
    super(vc);
  }

  @Override
  public Extension deserialize(
      final JsonParser p, final DeserializationContext ctxt) throws IOException
  {
    if (p.currentName().equals(Vulnerability10.VULNERABILITIES)) {
      if (p instanceof FromXmlParser) {
        return processVulnerabilities(p);
      } else {
        return processJsonVulnerabilities(p);
      }
    }
    return null;
  }

  private Extension processJsonVulnerabilities(final JsonParser parser) throws IOException {
    Vulnerability10[] vulns = parser.readValueAs(Vulnerability10[].class);
    Extension ext = new Extension();
    ext.setExtensions(Arrays.asList(vulns));

    return ext;
  }

  private Extension processVulnerabilities(final JsonParser parser) throws IOException {
    TreeNode treeNode =  parser.readValueAsTree();
    JsonNode vulnerabilityNode = (JsonNode) treeNode.get(Vulnerability10.NAME);
    List<ExtensibleType> extensibleTypes = new ArrayList<>();
    if (vulnerabilityNode != null) {
      if (vulnerabilityNode.isArray() && !vulnerabilityNode.isEmpty()) {
        for (JsonNode jn : vulnerabilityNode) {
          Vulnerability10 vulnerability = processVulnerability(jn);
          extensibleTypes.add(vulnerability);
        }
      } else {
        Vulnerability10 vuln = processVulnerability(vulnerabilityNode);
        extensibleTypes.add(vuln);
      }
    }
    if (!extensibleTypes.isEmpty()) {
      return createAndReturnExtension(ExtensionType.VULNERABILITIES, extensibleTypes);
    }
    return null;
  }

  private Vulnerability10 processVulnerability(final JsonNode vulnJson) {
    Vulnerability10 vuln = new Vulnerability10();
    for (Iterator<String> it = vulnJson.fieldNames(); it.hasNext(); ) {
      String field = it.next();
      switch (field) {
        case Vulnerability10.REF:
          vuln.setRef(vulnJson.get(field).textValue());
          break;
        case Vulnerability10.ID:
          vuln.setId(vulnJson.get(field).textValue());
          break;
        case Vulnerability10.SOURCE:
          vuln.setSource(processSource(vulnJson.get(field)));
          break;
        case Vulnerability10.RATINGS:
          vuln.setRatings(processRatings(vulnJson.get(field)));
          break;
        case Vulnerability10.CWES:
          vuln.setCwes(processCwes(vulnJson.get(field)));
          break;
        case Vulnerability10.DESCRIPTION:
          vuln.setDescription(vulnJson.get(field).textValue());
          break;
        case Vulnerability10.RECOMMENDATIONS:
          vuln.setRecommendations(processRecommendations(vulnJson.get(field)));
          break;
        case Vulnerability10.ADVISORIES:
          vuln.setAdvisories(processAdvisories(vulnJson.get(field)));
          break;
        default:
          // Unsupported field, skipped and not deserialized
          break;
      }
    }
    return vuln;
  }

  private List<Advisory> processAdvisories(final JsonNode advisories) {
    List<Advisory> advisoryList = new ArrayList<>();
    JsonNode adv = advisories.get(Vulnerability10.ADVISORY);
    if (adv != null) {
      if (adv.isArray() && !adv.isEmpty()) {
        for (JsonNode a : adv) {
          advisoryList.add(processAdvisory(a));
        }
      } else {
        advisoryList.add(processAdvisory(adv));
      }
    }
    return advisoryList.isEmpty() ? null : advisoryList;
  }

  private Advisory processAdvisory(final JsonNode advisory) {
    Advisory adv = new Advisory();
    adv.setText(advisory.textValue());
    return adv;
  }

  private List<Recommendation> processRecommendations(final JsonNode recommendations) {
    List<Recommendation> recommendationsList = new ArrayList<>();
    JsonNode rec = recommendations.get(Vulnerability10.RECOMMENDATION);
    if (rec != null) {
      if (rec.isArray() && !rec.isEmpty()) {
        for (JsonNode r : rec) {
          recommendationsList.add(processRecommendation(r));
        }
      } else {
        recommendationsList.add(processRecommendation(rec));
      }
    }
    return recommendationsList.isEmpty() ? null : recommendationsList;
  }

  private Recommendation processRecommendation(final JsonNode recommendation) {
    Recommendation rec = new Recommendation();
    rec.setText(recommendation.textValue());
    return rec;
  }

  private List<Cwe> processCwes(final JsonNode cwes) {
    List<Cwe> cweList = new ArrayList<>();
    JsonNode cwe = cwes.get(Vulnerability10.CWE);
    if (cwe != null) {
      if (cwe.isArray() && !cwe.isEmpty()) {
        for (JsonNode c : cwe) {
          cweList.add(processCwe(c));
        }
      } else {
        cweList.add(processCwe(cwe));
      }
    }
    return cweList.isEmpty() ? null : cweList;
  }

  private Cwe processCwe(final JsonNode cwe) {
    Cwe c = new Cwe();
    if (NumberUtils.isParsable(cwe.textValue())) {
      c.setText(Integer.valueOf(cwe.textValue()));
    }
    return c;
  }

  private Vulnerability10.Source processSource(final JsonNode sourceNode) {
    Source source = new Source();
    source.setName(getAsString("name", sourceNode));
    if (sourceNode.get(Vulnerability10.URL) != null) {
      try {
        source.setUrl(new URL(sourceNode.get(Vulnerability10.URL).textValue()));
      }
      catch (MalformedURLException e) {
        // Should we throw an exception? Is this worth stopping things over?
        e.printStackTrace();
      }
    }

    return source;
  }

  private List<Rating> processRatings(final JsonNode ratings) {
    List<Rating> ratingsList = new ArrayList<>();
    if (ratings != null) {
      if (ratings.isArray() && !ratings.isEmpty()) {
        for (JsonNode rating : ratings) {
          ratingsList.add(processRating(rating));
        }
      } else {
        ratingsList.add(processRating(ratings));
      }
    }
    return ratingsList.isEmpty() ? null : ratingsList;
  }

  private Rating processRating(final JsonNode ratingNode) {
    Rating rating = new Rating();
    JsonNode r = ratingNode.get(Vulnerability10.RATING);
    if (r != null) {
      if (r.get(Vulnerability10.SCORE) != null) {
        Score score = new Score();
        JsonNode s = r.get(Vulnerability10.SCORE);
        score.setBase(getAsDouble(Vulnerability10.BASE, s));
        score.setImpact(getAsDouble(Vulnerability10.IMPACT, s));
        score.setExploitability(getAsDouble(Vulnerability10.EXPLOITABILITY, s));
        rating.setScore(score);
      }
      rating.setSeverity(Severity.fromString(getAsString(Vulnerability10.SEVERITY, r)));
      rating.setMethod(ScoreSource.fromString(getAsString(Vulnerability10.METHOD, r)));
      rating.setVector(getAsString(Vulnerability10.VECTOR, r));
    }

    return rating;
  }

  private Extension createAndReturnExtension(final ExtensionType extType, final List<ExtensibleType> list) {
    if (extType == ExtensionType.VULNERABILITIES) {
      Extension ext = new Extension(extType, list);

      ext.setNamespaceURI(Vulnerability10.NAMESPACE_URI);
      ext.setPrefix(Vulnerability10.PREFIX);

      return ext;
    }
    return null;
  }

  private Double getAsDouble(final String fieldName, final JsonNode node) {
    if (node.get(fieldName) != null) {
      return node.get(fieldName).asDouble();
    }
    return null;
  }

  private String getAsString(final String fieldName, final JsonNode node) {
    if (node.get(fieldName) != null) {
      return node.get(fieldName).textValue();
    }
    return null;
  }
}
