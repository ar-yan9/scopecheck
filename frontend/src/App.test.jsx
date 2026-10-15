import React from 'react';
import {describe,it,expect,vi,afterEach} from 'vitest';
import {render,screen,fireEvent,waitFor,cleanup} from '@testing-library/react';
import '@testing-library/jest-dom/vitest';
import {App} from './App.jsx';
afterEach(()=>{cleanup();vi.unstubAllGlobals()});
describe('authorization and honest reporting',()=>{
 it('disables scanning until permission is checked',()=>{render(<App/>);expect(screen.getAllByRole('button',{name:/Run authorized/})[0]).toBeDisabled()});
 it('sends only selected inputs and shows errors',async()=>{const fetch=vi.fn().mockResolvedValue({ok:false,json:async()=>({detail:'Outside authorized scope'})});vi.stubGlobal('fetch',fetch);render(<App/>);const checks=screen.getAllByRole('checkbox');fireEvent.click(checks.at(-1));fireEvent.click(screen.getAllByRole('button',{name:/Run authorized/}).at(-1));await waitFor(()=>expect(screen.getByRole('alert')).toHaveTextContent('Outside authorized scope'));expect(fetch.mock.calls[0][0]).toBe('/api/scan');expect(JSON.parse(fetch.mock.calls[0][1].body).authorized).toBe(true)});
});
