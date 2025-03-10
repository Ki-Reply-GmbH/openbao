import { module, test } from 'qunit';
import { setupRenderingTest } from 'ember-qunit';
import { render } from '@ember/test-helpers';
import hbs from 'htmlbars-inline-precompile';
import { stubFeaturesAndPermissions } from 'vault/tests/helpers/components/sidebar-nav';

const renderComponent = () => {
  return render(hbs`
    <Sidebar::Frame @isVisible={{true}}>
      <Sidebar::Nav::Policies />
    </Sidebar::Frame>
  `);
};

module('Integration | Component | sidebar-nav-policies', function (hooks) {
  setupRenderingTest(hooks);

  test('it should hide links user does not have access too', async function (assert) {
    await renderComponent();
    assert
      .dom('[data-test-sidebar-nav-link]')
      .exists({ count: 1 }, 'Nav links are hidden other than back link');
  });

  test('it should render nav headings and links', async function (assert) {
    const links = ['Back to main navigation', 'ACL Policies'];
    stubFeaturesAndPermissions(this.owner);
    await renderComponent();

    assert.dom('[data-test-sidebar-nav-heading]').exists({ count: 1 }, 'Correct number of headings render');
    assert.dom('[data-test-sidebar-nav-heading="Policies"]').hasText('Policies', 'Policies heading renders');

    assert
      .dom('[data-test-sidebar-nav-link]')
      .exists({ count: links.length }, 'Correct number of links render');
    links.forEach((link) => {
      assert.dom(`[data-test-sidebar-nav-link="${link}"]`).hasText(link, `${link} link renders`);
    });
  });
});
