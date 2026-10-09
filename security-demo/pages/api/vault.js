export default function handler(request, response) {
  response.status(200).json({ id: 'inv_a', tenant: 'a', amount_minor: 1299, currency: 'usd', synthetic: true })
}
