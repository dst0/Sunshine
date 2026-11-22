import { mount, RouterLinkStub } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import Navbar from '../../src_assets/common/assets/web/Navbar.vue'

describe('Sunshine navigation', () => {
  it('renders the routes to pairing, configuration and account settings', () => {
    const wrapper = mount(Navbar, {
      global: {
        mocks: { $t: key => key },
        stubs: { RouterLink: RouterLinkStub, ThemeToggle: true, Notification: true },
      },
    })

    const routes = wrapper.findAllComponents(RouterLinkStub).map(link => link.props('to'))
    expect(routes).toEqual(expect.arrayContaining(['/pin', '/config', '/password']))
    wrapper.unmount()
  })
})
