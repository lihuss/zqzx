<template>
  <view class="container">
    <web-view :src="url"></web-view>
  </view>
</template>

<script>
export default {
  data() {
    return {
      // 这里的地址需要根据实际情况修改
      // 1. 如果是 H5 预览，可以直接填 localhost:3000
      // 2. 如果是真机调试，需要填电脑的局域网 IP (例如 http://192.168.1.x:3000)
      // 3. 如果已部署到服务器，填服务器域名
      url: 'http://localhost:3000'
    }
  },
  onLoad() {},
  methods: {},
}
</script>

<style>
.container {
  width: 100%;
  height: 100%;
}
</style>
