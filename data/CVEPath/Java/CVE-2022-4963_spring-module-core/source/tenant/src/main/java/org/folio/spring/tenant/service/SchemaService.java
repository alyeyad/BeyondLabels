package org.folio.spring.tenant.service;

import org.folio.spring.tenant.properties.BuildInfoProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class SchemaService {

  @Autowired
  private BuildInfoProperties buildInfoProperties;

  public String getSchema(String tenant) {
    return String.format("%s_%s", tenant, buildInfoProperties.getArtifact()).replace("-", "_");
  }

}
