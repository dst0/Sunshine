<template>
  <Navbar-Simple></Navbar-Simple>
  <main id="content" class="container" role="main">
    <h1 class="my-4">{{ $t('welcome.greeting') }}</h1>
    <div class="card">
      <div class="card-body">
        <div class="alert alert-warning">
          {{ $t('welcome.no_creds') }}
        </div>
        <p>{{ $t('welcome.create_creds_cli') }}</p>
        <pre class="mb-3"><code>sunshine --creds &lt;username&gt;</code></pre>
        <p class="mb-0">{{ $t('welcome.create_creds_restart') }}</p>
      </div>
    </div>
  </main>
</template>

<script>
  import NavbarSimple from './NavbarSimple.vue'

  /**
   * First-run page shown when no Web UI credentials exist.
   *
   * Credentials cannot be created from the browser: an unauthenticated page that sets the admin
   * password would let anyone who reaches the Web UI first take it over. The page only explains
   * how to create them on the host.
   */
  export default {
    components: {
      NavbarSimple,
    },
  }
</script>
