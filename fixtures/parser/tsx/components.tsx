import React, { forwardRef, memo, useMemo } from "react";

type Props = {
  name: string;
};

export function ProfileCard({ name }: Props) {
  return <section>{name}</section>;
}

export const InlineCard = ({ name }: Props) => <div>{name}</div>;

export const MemoCard = memo(function MemoCardInner({ name }: Props) {
  return <div>{name}</div>;
});

export const ForwardedInput = forwardRef<HTMLInputElement, Props>(function ForwardedInput(
  props,
  ref,
) {
  return <input ref={ref} value={props.name} />;
});

export function useProfile(name: string) {
  return useMemo(() => ({ name }), [name]);
}

React;
