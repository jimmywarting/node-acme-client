/* eslint-disable */
// const {Worker} = require('worker_threads')

async function mainWorkerThread() {
  const evt = await new Promise(rs => {
    self.addEventListener('message', evt => rs(evt), { once: true })
  })
  const shared = evt.data
  console.log(0, shared)
}

async function asyncWorkerThread() {
  const evt = await new Promise(rs => {
    self.addEventListener('message', evt => rs(evt), { once: true })
  })
  const shared = evt.data
  console.log(1, shared)
}

const shared = new SharedArrayBuffer(4)
const workers = [mainWorkerThread, asyncWorkerThread].map(fn => {
	const code = fn.toString() + `\n${fn.name}()`
  const blob = new Blob([code], { type: 'text/javascript' })
  const url = URL.createObjectURL(blob)
  const worker = new Worker(url, { type: 'module' })
  worker.postMessage(shared)
  return worker
})

console.log(workers)