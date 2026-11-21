<script setup>
import { computed, ref } from 'vue'
import Checkbox from '../../Checkbox.vue'

const props = defineProps({
  platform: String,
  config: Object,
})

const config = ref(props.config)

/**
 * Permissions a newly paired client can be granted by default (DESIGN 4.2).
 */
const permissionNames = ['clipboard_read', 'clipboard_write', 'file_upload', 'file_download', 'mic']

/**
 * The comma-separated `sds_default_permissions` value as a set of names.
 */
const defaultPermissions = computed(() => new Set(
  `${config.value.sds_default_permissions ?? ''}`
    .split(',')
    .map(name => name.trim())
    .filter(name => permissionNames.includes(name))
))

/**
 * Toggle one default permission and store the list in canonical order.
 *
 * @param {string} name Permission name.
 * @param {boolean} granted Whether the permission is granted by default.
 */
function setDefaultPermission(name, granted) {
  const selected = new Set(defaultPermissions.value)
  if (granted) {
    selected.add(name)
  } else {
    selected.delete(name)
  }
  config.value.sds_default_permissions = permissionNames.filter(permission => selected.has(permission)).join(',')
}
</script>

<template>
  <div id="sds" class="config-page">
    <!-- Global feature switches -->
    <Checkbox class="mb-3"
              id="clipboard"
              locale-prefix="config"
              v-model="config.clipboard"
              default="true"
    ></Checkbox>
    <Checkbox class="mb-3"
              id="file_transfer"
              locale-prefix="config"
              v-model="config.file_transfer"
              default="true"
    ></Checkbox>
    <Checkbox class="mb-3"
              id="mic_passthrough"
              locale-prefix="config"
              v-model="config.mic_passthrough"
              default="true"
    ></Checkbox>

    <!-- Clipboard limits -->
    <div class="mb-3">
      <label for="clipboard_text_max" class="form-label">{{ $t('config.clipboard_text_max') }}</label>
      <input type="text" class="form-control" id="clipboard_text_max" placeholder="1M" v-model="config.clipboard_text_max" />
      <div class="form-text">{{ $t('config.clipboard_text_max_desc') }}</div>
    </div>
    <div class="mb-3">
      <label for="clipboard_image_max" class="form-label">{{ $t('config.clipboard_image_max') }}</label>
      <input type="text" class="form-control" id="clipboard_image_max" placeholder="16M" v-model="config.clipboard_image_max" />
      <div class="form-text">{{ $t('config.clipboard_image_max_desc') }}</div>
    </div>
    <div class="mb-3">
      <label for="clipboard_rate" class="form-label">{{ $t('config.clipboard_rate') }}</label>
      <input type="number" min="1" max="1000" class="form-control" id="clipboard_rate" placeholder="10" v-model="config.clipboard_rate" />
      <div class="form-text">{{ $t('config.clipboard_rate_desc') }}</div>
    </div>

    <!-- File transfer limits -->
    <div class="mb-3">
      <label for="file_max" class="form-label">{{ $t('config.file_max') }}</label>
      <input type="text" class="form-control" id="file_max" placeholder="4G" v-model="config.file_max" />
      <div class="form-text">{{ $t('config.file_max_desc') }}</div>
    </div>
    <div class="mb-3">
      <label for="file_chunk_max" class="form-label">{{ $t('config.file_chunk_max') }}</label>
      <input type="text" class="form-control" id="file_chunk_max" placeholder="4M" v-model="config.file_chunk_max" />
      <div class="form-text">{{ $t('config.file_chunk_max_desc') }}</div>
    </div>
    <div class="mb-3">
      <label for="file_uploads_max_concurrent" class="form-label">{{ $t('config.file_uploads_max_concurrent') }}</label>
      <input type="number" min="1" max="16" class="form-control" id="file_uploads_max_concurrent" placeholder="2" v-model="config.file_uploads_max_concurrent" />
      <div class="form-text">{{ $t('config.file_uploads_max_concurrent_desc') }}</div>
    </div>
    <div class="mb-3">
      <label for="file_min_free_space" class="form-label">{{ $t('config.file_min_free_space') }}</label>
      <input type="text" class="form-control" id="file_min_free_space" placeholder="1G" v-model="config.file_min_free_space" />
      <div class="form-text">{{ $t('config.file_min_free_space_desc') }}</div>
    </div>
    <div class="mb-3">
      <label for="file_upload_idle_timeout" class="form-label">{{ $t('config.file_upload_idle_timeout') }}</label>
      <input type="number" min="10" max="86400" class="form-control" id="file_upload_idle_timeout" placeholder="120" v-model="config.file_upload_idle_timeout" />
      <div class="form-text">{{ $t('config.file_upload_idle_timeout_desc') }}</div>
    </div>

    <!-- Folders -->
    <div class="mb-3">
      <label for="file_inbox_dir" class="form-label">{{ $t('config.file_inbox_dir') }}</label>
      <input type="text" class="form-control" id="file_inbox_dir" placeholder="~/Downloads/Moonlight" v-model="config.file_inbox_dir" />
      <div class="form-text">{{ $t('config.file_inbox_dir_desc') }}</div>
    </div>
    <div class="mb-3">
      <label for="file_outbox_dir" class="form-label">{{ $t('config.file_outbox_dir') }}</label>
      <input type="text" class="form-control" id="file_outbox_dir" placeholder="~/Downloads/Moonlight/Outbox" v-model="config.file_outbox_dir" />
      <div class="form-text">{{ $t('config.file_outbox_dir_desc') }}</div>
    </div>

    <!-- Default permissions for new pairings -->
    <div class="mb-3" id="sds_default_permissions">
      <div class="form-label">{{ $t('config.sds_default_permissions') }}</div>
      <div class="form-check" v-for="name in permissionNames" :key="name">
        <input class="form-check-input" type="checkbox" :id="'sds_default_permission_' + name"
               :checked="defaultPermissions.has(name)"
               @change="setDefaultPermission(name, $event.target.checked)" />
        <label class="form-check-label" :for="'sds_default_permission_' + name">
          {{ $t('config.sds_permission_' + name) }}
        </label>
      </div>
      <div class="form-text">{{ $t('config.sds_default_permissions_desc') }}</div>
    </div>
  </div>
</template>
