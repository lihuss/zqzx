<template>
  <view class="container">
    <web-view :src="url"></web-view>
  </view>
</template>

<script>
export default {
  data() {
    return {
      // 连云端服务器
      url: 'http://112.74.54.5:3000'
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
