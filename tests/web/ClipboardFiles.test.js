import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('../../src_assets/common/assets/web/Navbar.vue', () => ({
  default: { template: '<div />' },
}))

import ClipboardFiles from '../../src_assets/common/assets/web/configs/tabs/ClipboardFiles.vue'
import Troubleshooting from '../../src_assets/common/assets/web/Troubleshooting.vue'
import { resetCsrfTokenCacheForTesting } from '../../src_assets/common/assets/web/fetch_utils.js'
import configTabs from '../../src_assets/common/assets/web/configs/config_tabs.json'
import en from '../../src_assets/common/assets/web/public/assets/locale/en.json'

const globalOptions = {
  mocks: {
    $t: key => key,
  },
  stubs: {
    Checkbox: true,
  },
}

/**
 * @brief Mount the Clipboard & Files tab with the given configuration.
 *
 * @param {object} config Configuration values.
 * @return {object} Mounted wrapper.
 */
function mountTab(config) {
  return mount(ClipboardFiles, {
    props: { platform: 'linux', config },
    global: globalOptions,
  })
}

/**
 * @brief Respond to the requests Troubleshooting makes on mount.
 *
 * @param {string} url Requested URL.
 * @return {object|null} Fake response, or null for URLs the caller handles.
 */
function baseResponse(url) {
  if (url === '/api/config') {
    return { json: async () => ({ platform: 'linux', gamepad_driver: '' }) }
  }
  if (url === '/api/virtual-input/status') {
    return {
      json: async () => ({
        virtualhid: { installed: true, version: '2026.914.1218', version_compatible: true, supported_versions: '>= 2026.914.1218' },
        vigembus: { installed: false },
      }),
    }
  }
  if (url === '/api/virtual-input/license') {
    return { ok: true, json: async () => ({ service_available: true, state: 'licensed', licensed: true }) }
  }
  if (url === './api/permissions') {
    return { ok: true, json: async () => ({ permissions: [] }) }
  }
  if (url === './api/logs') {
    return { text: async () => '' }
  }
  if (url === './api/csrf-token') {
    return { ok: true, status: 200, json: async () => ({ csrf_token: 'test-csrf-token' }) }
  }
  return null
}

describe('Clipboard & Files configuration tab', () => {
  it('is registered with defaults for every option and English labels', () => {
    const tab = configTabs.find(entry => entry.id === 'sds')
    expect(tab).toBeDefined()
    expect(tab.nameKey).toBe('config.category_clipboard_files')
    expect(Object.keys(tab.options)).toEqual([
      'clipboard', 'file_transfer', 'file_clipboard', 'mic_passthrough', 'clipboard_text_max', 'clipboard_image_max', 'clipboard_rate',
      'file_max', 'file_chunk_max', 'file_uploads_max_concurrent', 'file_min_free_space', 'file_upload_idle_timeout',
      'file_inbox_dir', 'file_outbox_dir', 'sds_default_permissions',
    ])
    expect(tab.options.sds_default_permissions).toBe('')
    for (const key of Object.keys(tab.options)) {
      expect(en.config[key], key).toBeTruthy()
      expect(en.config[`${key}_desc`], `${key}_desc`).toBeTruthy()
    }
  })

  it('labels every input', () => {
    const wrapper = mountTab({ ...configTabs.find(entry => entry.id === 'sds').options })
    for (const input of wrapper.findAll('input')) {
      expect(wrapper.find(`label[for="${input.attributes('id')}"]`).exists(), input.attributes('id')).toBe(true)
    }
  })

  it('edits default permissions as a canonical comma-separated list', async () => {
    const config = { sds_default_permissions: 'mic, bogus,clipboard_read' }
    const wrapper = mountTab(config)
    expect(wrapper.get('#sds_default_permission_clipboard_read').element.checked).toBe(true)
    expect(wrapper.get('#sds_default_permission_mic').element.checked).toBe(true)
    expect(wrapper.get('#sds_default_permission_file_upload').element.checked).toBe(false)

    await wrapper.get('#sds_default_permission_file_upload').setValue(true)
    expect(config.sds_default_permissions).toBe('clipboard_read,file_upload,mic')
    await wrapper.get('#sds_default_permission_mic').setValue(false)
    expect(config.sds_default_permissions).toBe('clipboard_read,file_upload')
  })
})

describe('client permission toggles', () => {
  afterEach(() => {
    resetCsrfTokenCacheForTesting()
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  it('shows and updates per-client permissions', async () => {
    const posted = []
    let lastCsrfHeader = null
    let permissions = ['clipboard_read']
    vi.stubGlobal('fetch', vi.fn(async (url, options) => {
      if (url === './api/clients/list') {
        return { json: async () => ({ status: true, named_certs: [{ name: 'Mac', uuid: 'u1', enabled: true, permissions }] }) }
      }
      if (url === './api/clients/permissions') {
        lastCsrfHeader = options?.headers?.['X-CSRF-Token'] ?? null
        const body = JSON.parse(options.body)
        posted.push(body)
        permissions = body.permissions
        return { status: 200, json: async () => ({ status: true, permissions }) }
      }
      return baseResponse(url) ?? { ok: true, json: async () => ({ tag_name: 'v2026.914.1218.10', html_url: 'https://example.com/release' }) }
    }))

    const wrapper = mount(Troubleshooting, {
      global: { mocks: { $t: key => key }, stubs: { Navbar: true, RouterLink: true } },
    })
    await flushPromises()

    expect(wrapper.get('#permission-clipboard_read-u1').element.checked).toBe(true)
    expect(wrapper.get('#permission-file_upload-u1').element.checked).toBe(false)
    expect(wrapper.find('label[for="permission-mic-u1"]').text()).toBe('troubleshooting.sds_permission_mic')

    await wrapper.get('#permission-file_upload-u1').setValue(true)
    await flushPromises()
    expect(posted).toEqual([{ uuid: 'u1', permissions: ['clipboard_read', 'file_upload'] }])
    expect(lastCsrfHeader).toBe('test-csrf-token')
    expect(wrapper.get('#permission-file_upload-u1').element.checked).toBe(true)
    expect(wrapper.find('.alert-danger').exists()).toBe(false)
  })

  it('reports failed permission updates', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url) => {
      if (url === './api/clients/list') {
        return { json: async () => ({ status: true, named_certs: [{ name: '', uuid: 'u2', enabled: true }] }) }
      }
      if (url === './api/clients/permissions') {
        return { status: 200, json: async () => ({ status: false }) }
      }
      return baseResponse(url) ?? { ok: true, json: async () => ({ tag_name: 'v2026.914.1218.10', html_url: 'https://example.com/release' }) }
    }))

    const wrapper = mount(Troubleshooting, {
      global: { mocks: { $t: key => key }, stubs: { Navbar: true, RouterLink: true } },
    })
    await flushPromises()
    expect(wrapper.get('#permission-mic-u2').element.checked).toBe(false)
    await wrapper.get('#permission-mic-u2').setValue(true)
    await flushPromises()
    expect(wrapper.text()).toContain('troubleshooting.sds_permissions_error')
  })
})
