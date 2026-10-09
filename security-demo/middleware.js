import { NextResponse } from 'next/server'
export function middleware(request) {
  if (request.headers.get('x-demo-auth') !== 'a') {
    return NextResponse.json({ error: 'synthetic invoice auth required' }, { status: 401 })
  }
  return NextResponse.next()
}
export const config = { matcher: ['/api/vault'] }
