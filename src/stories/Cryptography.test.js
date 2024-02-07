import { TextEncoder, TextDecoder } from 'util'
global.TextEncoder = TextEncoder
// @ts-expect-error
global.TextDecoder = TextDecoder

const crypto = require('crypto');

Object.defineProperty(globalThis, 'crypto', {
  value: {
    getRandomValues: arr => crypto.randomBytes(arr.length)
  }
});

//add polyfill for window.alert()
global.alert = jest.fn();

import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { composeStory } from "@storybook/react";
import "@testing-library/jest-dom";

import Cryptography, { Basic as ExampleBasic } from "./Cryptography.stories"; // 👈 Import the story and its metadata
import { expect } from "@storybook/test";

const BasicExample = composeStory(ExampleBasic, Cryptography);

test("Checks if the Example component renders with children and triggers onClick", () => {
  render(<BasicExample {...ExampleBasic.args} />);

  const component = screen.getByText("positive-intentions");
  expect(component).toHaveTextContent("positive-intentions");
});
