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
package org.cyclonedx.generators.json;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.cyclonedx.CycloneDxSchema;
import org.cyclonedx.exception.GeneratorException;
import org.cyclonedx.model.Bom;
import org.cyclonedx.util.CollectionTypeSerializer;
import org.cyclonedx.util.ComponentWrapperSerializer;
import org.cyclonedx.util.LicenseChoiceSerializer;
import org.cyclonedx.util.TrimStringSerializer;
import org.cyclonedx.util.VersionAnnotationIntrospector;
import org.cyclonedx.util.XmlOnlyAnnotationIntrospector;

abstract class AbstractBomJsonGenerator extends CycloneDxSchema implements BomJsonGenerator {

    private final ObjectMapper mapper;

    private final DefaultPrettyPrinter prettyPrinter;

    AbstractBomJsonGenerator() {
        this.mapper = new ObjectMapper();
        this.prettyPrinter = new DefaultPrettyPrinter();

        setupObjectMapper(this.mapper);
        setupPrettyPrinter(this.prettyPrinter);
    }

    private void setupPrettyPrinter(final DefaultPrettyPrinter prettyPrinter) {
        prettyPrinter.indentArraysWith(DefaultIndenter.SYSTEM_LINEFEED_INSTANCE);
    }

    private void setupObjectMapper(final ObjectMapper mapper) {
        SimpleModule licenseModule = new SimpleModule();
        SimpleModule depModule = new SimpleModule();
        SimpleModule componentWrapperModule = new SimpleModule();

        mapper.setAnnotationIntrospector(
            new XmlOnlyAnnotationIntrospector());

        SimpleModule stringModule = new SimpleModule();
        stringModule.addSerializer(new TrimStringSerializer());
        mapper.registerModule(stringModule);

        licenseModule.addSerializer(new LicenseChoiceSerializer());

        mapper.registerModule(licenseModule);

        depModule.setSerializers(new CollectionTypeSerializer(false));
        mapper.registerModule(depModule);

        componentWrapperModule.addSerializer(new ComponentWrapperSerializer(mapper));

        mapper.registerModule(componentWrapperModule);
    }

    String toJson(final Bom bom, final boolean prettyPrint) throws GeneratorException {
        try {
            if (prettyPrint) {
                return mapper.writer(prettyPrinter).writeValueAsString(bom);
            }
            return mapper.writeValueAsString(bom);
        }
        catch (JsonProcessingException e) {
            throw new GeneratorException(e);
        }
    }
}
