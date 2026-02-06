export type RequiredNonNullable<T> = { [P in keyof T]-?: NonNullable<T[P]> };
