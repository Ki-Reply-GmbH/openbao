/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */
import Controller from '@ember/controller';
import { inject as service } from '@ember/service';
import { action } from '@ember/object';
import { tracked } from '@glimmer/tracking';
import { createCache, getValue } from '@glimmer/tracking/primitives/cache';
import { dropTask } from 'ember-concurrency';

export default class VaultClusterSecretsBackendController extends Controller {
  @service flashMessages;

  @tracked secretEngineOptions = [];
  @tracked selectedEngineType = null;
  @tracked selectedEngineName = null;

  #displayableBackendsCache = createCache(() => this.model.filter((be) => be.shouldIncludeInList));
  get displayableBackends() {
    return getValue(this.#displayableBackendsCache);
  }

  get sortedDisplayableBackends() {
    // show supported secret engines first and then organize those by id.
    const sortedBackends = this.displayableBackends.sort(
      (a, b) => b.isSupportedBackend - a.isSupportedBackend || a.id - b.id
    );

    // return an options list to filter by engine type, ex: 'kv'
    if (this.selectedEngineType) {
      // check first if the user has also filtered by name.
      if (this.selectedEngineName) {
        return sortedBackends.filter((backend) => this.selectedEngineName === backend.id);
      }
      // otherwise filter by engine type
      return sortedBackends.filter((backend) => this.selectedEngineType === backend.engineType);
    }

    // return an options list to filter by engine name, ex: 'secret'
    if (this.selectedEngineName) {
      return sortedBackends.filter((backend) => this.selectedEngineName === backend.id);
    }
    // no filters, return full sorted list.
    return sortedBackends;
  }

  get secretEngineArrayByType() {
    const arrayOfAllEngineTypes = this.sortedDisplayableBackends.map((modelObject) => modelObject.engineType);
    // filter out repeated engineTypes (e.g. [kv, kv] => [kv])
    const arrayOfUniqueEngineTypes = [...new Set(arrayOfAllEngineTypes)];

    return arrayOfUniqueEngineTypes.map((engineType) => ({
      name: engineType,
      id: engineType,
    }));
  }

  get secretEngineArrayByName() {
    return this.sortedDisplayableBackends.map((modelObject) => ({
      name: modelObject.id,
      id: modelObject.id,
    }));
  }

  @action
  filterEngineType([type]) {
    this.selectedEngineType = type;
  }

  @action
  filterEngineName([name]) {
    this.selectedEngineName = name;
  }

  @dropTask
  *disableEngine(engine) {
    const { engineType, path } = engine;
    try {
      yield engine.destroyRecord();
      this.flashMessages.success(`The ${engineType} Secrets Engine at ${path} has been disabled.`);
    } catch (err) {
      this.flashMessages.danger(
        `There was an error disabling the ${engineType} Secrets Engine at ${path}: ${err.errors.join(' ')}.`
      );
    }
  }
}
